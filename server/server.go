package chserver

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/gorilla/websocket"
	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/reality"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/requestlog"
	"golang.org/x/crypto/ssh"
)

// Config is the configuration for the chisel service
type Config struct {
	KeySeed   string
	KeyFile   string
	AuthFile  string
	Auth      string
	Proxy     string
	Socks5    bool
	Reverse   bool
	KeepAlive time.Duration
	TLS       TLSConfig
	Reality   RealityConfig
}

// RealityConfig for Reality authentication
type RealityConfig struct {
	Enabled    bool
	PrivateKey string // Base64-encoded private key
	ShortID    string // Optional short identifier
	Fallback   string // URL to proxy unauthenticated requests
}

// Server respresent a chisel service
type Server struct {
	*cio.Logger
	config       *Config
	fingerprint  string
	httpServer   *cnet.HTTPServer
	reverseProxy *httputil.ReverseProxy
	sessCount    int32
	sessions     *settings.Users
	sshConfig    *ssh.ServerConfig
	users        *settings.UserIndex
	// Reality authentication
	realityEnabled    bool
	realityPrivateKey [reality.KeySize]byte
	realityShortID    []byte
	realityFallback   string
}

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  settings.EnvInt("WS_BUFF_SIZE", 0),
	WriteBufferSize: settings.EnvInt("WS_BUFF_SIZE", 0),
}

// NewServer creates and returns a new chisel server
func NewServer(c *Config) (*Server, error) {
	server := &Server{
		config:     c,
		httpServer: cnet.NewHTTPServer(),
		Logger:     cio.NewLogger("server"),
		sessions:   settings.NewUsers(),
	}
	server.Info = true
	server.users = settings.NewUserIndex(server.Logger)
	if c.AuthFile != "" {
		if err := server.users.LoadUsers(c.AuthFile); err != nil {
			return nil, err
		}
	}
	if c.Auth != "" {
		u := &settings.User{Addrs: []*regexp.Regexp{settings.UserAllowAll}}
		u.Name, u.Pass = settings.ParseAuth(c.Auth)
		if u.Name != "" {
			server.users.AddUser(u)
		}
	}

	var pemBytes []byte
	var err error
	if c.KeyFile != "" {
		var key []byte

		if ccrypto.IsChiselKey([]byte(c.KeyFile)) {
			key = []byte(c.KeyFile)
		} else {
			key, err = os.ReadFile(c.KeyFile)
			if err != nil {
				log.Fatalf("Failed to read key file %s", c.KeyFile)
			}
		}

		pemBytes = key
		if ccrypto.IsChiselKey(key) {
			pemBytes, err = ccrypto.ChiselKey2PEM(key)
			if err != nil {
				log.Fatalf("Invalid key %s", string(key))
			}
		}
	} else {
		//generate private key (optionally using seed)
		pemBytes, err = ccrypto.Seed2PEM(c.KeySeed)
		if err != nil {
			log.Fatal("Failed to generate key")
		}
	}

	//convert into ssh.PrivateKey
	private, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatal("Failed to parse key")
	}
	//fingerprint this key
	server.fingerprint = ccrypto.FingerprintKey(private.PublicKey())
	//create ssh config
	server.sshConfig = &ssh.ServerConfig{
		ServerVersion:    "SSH-" + chshare.ProtocolVersion + "-server",
		PasswordCallback: server.authUser,
	}
	server.sshConfig.AddHostKey(private)
	//setup reverse proxy
	if c.Proxy != "" {
		u, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, err
		}
		if u.Host == "" {
			return nil, server.Errorf("Missing protocol (%s)", u)
		}
		server.reverseProxy = httputil.NewSingleHostReverseProxy(u)
		//always use proxy host
		server.reverseProxy.Director = func(r *http.Request) {
			//enforce origin, keep path
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
			r.Host = u.Host
		}
	}
	//print when reverse tunnelling is enabled
	if c.Reverse {
		server.Infof("Reverse tunnelling enabled")
	}
	// Configure Reality authentication
	if c.Reality.Enabled || c.Reality.PrivateKey != "" {
		if c.Reality.PrivateKey == "" {
			return nil, errors.New("Reality private key is required when Reality is enabled")
		}
		privkeyBytes, err := base64.StdEncoding.DecodeString(c.Reality.PrivateKey)
		if err != nil || len(privkeyBytes) != reality.KeySize {
			return nil, errors.New("Invalid Reality private key (must be 32 bytes, base64 encoded)")
		}
		server.realityEnabled = true
		copy(server.realityPrivateKey[:], privkeyBytes)
		if c.Reality.ShortID != "" {
			server.realityShortID = []byte(c.Reality.ShortID)
		}
		server.realityFallback = c.Reality.Fallback
		if server.realityFallback == "" {
			server.realityFallback = "https://www.microsoft.com"
		}
		server.Infof("Reality authentication enabled (fallback: %s)", server.realityFallback)
	}
	return server, nil
}

// Run is responsible for starting the chisel service.
// Internally this calls Start then Wait.
func (s *Server) Run(host, port string) error {
	if err := s.Start(host, port); err != nil {
		return err
	}
	return s.Wait()
}

// Start is responsible for kicking off the http server
func (s *Server) Start(host, port string) error {
	return s.StartContext(context.Background(), host, port)
}

// StartContext is responsible for kicking off the http server,
// and can be closed by cancelling the provided context
func (s *Server) StartContext(ctx context.Context, host, port string) error {
	s.Infof("Fingerprint %s", s.fingerprint)
	if s.users.Len() > 0 {
		s.Infof("User authentication enabled")
	}
	if s.reverseProxy != nil {
		s.Infof("Reverse proxy enabled")
	}
	l, err := s.listener(host, port)
	if err != nil {
		return err
	}
	h := http.Handler(http.HandlerFunc(s.handleClientHandler))
	if s.Debug {
		o := requestlog.DefaultOptions
		o.TrustProxy = true
		h = requestlog.WrapWith(h, o)
	}
	return s.httpServer.GoServe(ctx, l, h)
}

// Wait waits for the http server to close
func (s *Server) Wait() error {
	return s.httpServer.Wait()
}

// Close forcibly closes the http server
func (s *Server) Close() error {
	return s.httpServer.Close()
}

// GetFingerprint is used to access the server fingerprint
func (s *Server) GetFingerprint() string {
	return s.fingerprint
}

// authUser is responsible for validating the ssh user / password combination
func (s *Server) authUser(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// check if user authentication is enabled and if not, allow all
	if s.users.Len() == 0 {
		return nil, nil
	}
	// check the user exists and has matching password
	n := c.User()
	user, found := s.users.Get(n)
	if !found || user.Pass != string(password) {
		s.Debugf("Login failed for user: %s", n)
		return nil, errors.New("Invalid authentication for username: %s")
	}
	// insert the user session map
	// TODO this should probably have a lock on it given the map isn't thread-safe
	s.sessions.Set(string(c.SessionID()), user)
	return nil, nil
}

// AddUser adds a new user into the server user index
func (s *Server) AddUser(user, pass string, addrs ...string) error {
	authorizedAddrs := []*regexp.Regexp{}
	for _, addr := range addrs {
		authorizedAddr, err := regexp.Compile(addr)
		if err != nil {
			return err
		}
		authorizedAddrs = append(authorizedAddrs, authorizedAddr)
	}
	s.users.AddUser(&settings.User{
		Name:  user,
		Pass:  pass,
		Addrs: authorizedAddrs,
	})
	return nil
}

// DeleteUser removes a user from the server user index
func (s *Server) DeleteUser(user string) {
	s.users.Del(user)
}

// ResetUsers in the server user index.
// Use nil to remove all.
func (s *Server) ResetUsers(users []*settings.User) {
	s.users.Reset(users)
}

// authenticateReality verifies Reality authentication headers.
// Returns true if authentication succeeds (or Reality is disabled).
// Returns false if authentication fails (and proxies to fallback).
func (s *Server) authenticateReality(w http.ResponseWriter, r *http.Request) bool {
	if !s.realityEnabled {
		return true // Reality disabled, allow all
	}

	// Extract session ID from header
	sessionIDEncoded := r.Header.Get("X-Session-Id")
	if sessionIDEncoded == "" {
		s.Debugf("Reality auth: missing session ID header")
		s.proxyToFallback(w, r)
		return false
	}

	sessionIDBytes, err := base64.StdEncoding.DecodeString(sessionIDEncoded)
	if err != nil || len(sessionIDBytes) != reality.SessionIDSize {
		s.Debugf("Reality auth: invalid session ID format")
		s.proxyToFallback(w, r)
		return false
	}

	var sessionID [reality.SessionIDSize]byte
	copy(sessionID[:], sessionIDBytes)

	// Extract client public key from header
	clientPubKeyHeader := r.Header.Get("X-Client-Pubkey")
	if clientPubKeyHeader == "" {
		s.Debugf("Reality auth: missing client public key header")
		s.proxyToFallback(w, r)
		return false
	}

	clientPubKeyBytes, err := base64.StdEncoding.DecodeString(clientPubKeyHeader)
	if err != nil || len(clientPubKeyBytes) != reality.KeySize {
		s.Debugf("Reality auth: invalid client public key format")
		s.proxyToFallback(w, r)
		return false
	}

	var clientPubKey [reality.KeySize]byte
	copy(clientPubKey[:], clientPubKeyBytes)

	// Verify Reality authentication
	err = reality.VerifySessionID(sessionID, clientPubKey, s.realityPrivateKey, s.realityShortID)
	if err != nil {
		s.Debugf("Reality auth failed: %v", err)
		s.proxyToFallback(w, r)
		return false
	}

	s.Debugf("Reality auth succeeded")
	return true
}

// proxyToFallback proxies unauthenticated requests to the fallback website (anti-probing)
func (s *Server) proxyToFallback(w http.ResponseWriter, r *http.Request) {
	if s.realityFallback == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Parse fallback URL
	fallbackURL, err := url.Parse(s.realityFallback)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Create proxy request
	proxyURL := s.realityFallback + r.URL.Path
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Copy relevant headers (but not Reality-specific ones)
	for k, v := range r.Header {
		// Skip internal headers
		if k == "X-Session-Id" || k == "X-Client-Pubkey" {
			continue
		}
		proxyReq.Header[k] = v
	}

	// Set appropriate Host header
	proxyReq.Host = fallbackURL.Host

	// Forward request
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		s.Debugf("Fallback proxy error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}
