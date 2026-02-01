package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/chisel/share/reality"
	"github.com/xtaci/smux"
	utls "github.com/refraction-networking/utls"
)

// Fast TCP relay with Reality authentication - NO SSH overhead

var relayHelp = `
  Usage: chisel relay-server [options]
         chisel relay-client [options] <server> <local>:<remote>

  FAST TCP relay with Reality authentication (no SSH overhead).
  Designed to evade DPI by looking like normal HTTPS traffic.

  relay-server options:
    --port, -p         Port to listen on (default: 443)
    --tls-cert         TLS certificate file (auto-generated if not provided)
    --tls-key          TLS key file (auto-generated if not provided)
    --tls-domain       Domain for auto-generated cert (default: www.microsoft.com)
    --reality-privkey  Reality private key (from 'chisel genkey')
    --reality-shortid  Reality short ID
    -v                 Verbose logging

  relay-client options:
    --reality-pubkey   Reality public key
    --reality-shortid  Reality short ID
    --sni              SNI hostname to send (default: www.microsoft.com)
                       Use popular sites: google.com, microsoft.com, apple.com
    --tls-skip-verify  Skip TLS certificate verification (required for auto-cert)
    --mux              Number of parallel connections (1-8, default: 1)
                       Use --mux 4 for better web browsing performance
    -v                 Verbose logging

  DPI EVASION:
    - Uses uTLS with Chrome browser fingerprint
    - SNI spoofing to look like connecting to legitimate sites
    - ALPN negotiation (h2, http/1.1) like real browsers
    - Auto-generates TLS cert if none provided

  FORWARD MODE (client listens, server connects to target):
    chisel relay-client --sni google.com server:443 30949:localhost:30949

  REVERSE MODE (server listens, client connects to target):
    chisel relay-client --sni google.com server:443 R:30949:localhost:30949

  Examples:
    # === SERVER (Iran - has open IP) ===
    chisel relay-server -p 443 \
      --reality-privkey "..." --reality-shortid "..." -v

    # === CLIENT (Germany - behind NAT, has V2Ray on 30949) ===
    # Reverse mode: Iran listens on 30949, forwards to Germany's V2Ray
    chisel relay-client \
      --reality-pubkey "..." --reality-shortid "..." \
      --sni www.google.com --tls-skip-verify \
      iran-ip:443 R:30949:localhost:30949 -v

    # Traffic flow: User -> Iran:30949 -> [TLS tunnel] -> Germany:30949 (V2Ray)

`

const (
	bufferSize    = 32 * 1024 // 32KB buffer (balanced latency/throughput)
	authTimeout   = 10 * time.Second
	dialTimeout   = 10 * time.Second
	maxTargetLen  = 256
)

// reverseListener manages reverse tunnel listeners
type reverseListener struct {
	sync.RWMutex
	listeners map[string]*reverseSession
}

type reverseSession struct {
	listener    net.Listener
	controlConn net.Conn
	forwardAddr string
	connQueue   chan net.Conn
	verbose     bool
}

var globalReverse = &reverseListener{
	listeners: make(map[string]*reverseSession),
}

// generateSelfSignedCert creates a self-signed certificate for TLS
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{domain},
			CommonName:   domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "*." + domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// relayServer runs the fast relay server
func relayServer(args []string) {
	flags := flag.NewFlagSet("relay-server", flag.ContinueOnError)

	port := flags.String("port", "443", "")
	p := flags.String("p", "", "")
	tlsCert := flags.String("tls-cert", "", "")
	tlsKey := flags.String("tls-key", "", "")
	tlsDomain := flags.String("tls-domain", "www.microsoft.com", "")
	noTLS := flags.Bool("no-tls", false, "")
	realityPrivkey := flags.String("reality-privkey", "", "")
	realityShortID := flags.String("reality-shortid", "", "")
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() {
		fmt.Print(relayHelp)
		os.Exit(0)
	}
	flags.Parse(args)

	if *p != "" {
		*port = *p
	}

	// Parse Reality key
	var privKey [32]byte
	var shortID []byte
	realityEnabled := false

	if *realityPrivkey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(*realityPrivkey)
		if err != nil || len(keyBytes) != 32 {
			log.Fatal("Invalid reality private key")
		}
		copy(privKey[:], keyBytes)
		realityEnabled = true
		if *realityShortID != "" {
			shortID = []byte(*realityShortID)
		}
	}

	// Setup listener
	var listener net.Listener
	var err error

	addr := "0.0.0.0:" + *port

	if *noTLS {
		// Raw TCP (not recommended - DPI can detect)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (no TLS - NOT DPI resistant!)", addr)
	} else {
		// TLS mode (recommended for DPI evasion)
		var cert tls.Certificate
		if *tlsCert != "" && *tlsKey != "" {
			cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
			if err != nil {
				log.Fatalf("Failed to load TLS cert: %v", err)
			}
			log.Printf("relay-server: Using provided TLS certificate")
		} else {
			// Auto-generate self-signed cert
			cert, err = generateSelfSignedCert(*tlsDomain)
			if err != nil {
				log.Fatalf("Failed to generate TLS cert: %v", err)
			}
			log.Printf("relay-server: Auto-generated TLS cert for %s", *tlsDomain)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"}, // ALPN - looks like HTTP/2
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (TLS with ALPN h2)", addr)
	}

	if realityEnabled {
		log.Printf("relay-server: Reality authentication enabled")
	}

	var connID int64

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		id := atomic.AddInt64(&connID, 1)
		go handleRelayConnection(conn, id, privKey, shortID, realityEnabled, *verbose)
	}
}

func handleRelayConnection(conn net.Conn, id int64, privKey [32]byte, shortID []byte, realityEnabled, verbose bool) {
	conn.SetDeadline(time.Now().Add(authTimeout))

	// Read auth header (if Reality enabled)
	// Protocol: [2 bytes: auth len][auth data][1 byte: cmd len][cmd string]
	if realityEnabled {
		// Read auth length
		authLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, authLenBuf); err != nil {
			if verbose {
				log.Printf("[%d] Failed to read auth length: %v", id, err)
			}
			conn.Close()
			return
		}
		authLen := binary.BigEndian.Uint16(authLenBuf)
		if authLen < 64 || authLen > 128 {
			if verbose {
				log.Printf("[%d] Invalid auth length: %d", id, authLen)
			}
			conn.Close()
			return
		}

		// Read auth data (sessionID + clientPubKey)
		authData := make([]byte, authLen)
		if _, err := io.ReadFull(conn, authData); err != nil {
			if verbose {
				log.Printf("[%d] Failed to read auth: %v", id, err)
			}
			conn.Close()
			return
		}

		// Parse session ID (32 bytes) and client public key (32 bytes)
		if len(authData) < 64 {
			if verbose {
				log.Printf("[%d] Auth data too short", id)
			}
			conn.Close()
			return
		}

		var sessionID [32]byte
		var clientPubKey [32]byte
		copy(sessionID[:], authData[:32])
		copy(clientPubKey[:], authData[32:64])

		// Verify Reality auth
		if err := reality.VerifySessionID(sessionID, clientPubKey, privKey, shortID); err != nil {
			if verbose {
				log.Printf("[%d] Reality auth failed: %v", id, err)
			}
			conn.Close()
			return
		}

		if verbose {
			log.Printf("[%d] Reality auth OK", id)
		}
	}

	// Read command length
	cmdLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdLenBuf); err != nil {
		if verbose {
			log.Printf("[%d] Failed to read cmd length: %v", id, err)
		}
		conn.Close()
		return
	}
	cmdLen := int(cmdLenBuf[0])
	if cmdLen == 0 || cmdLen > maxTargetLen {
		if verbose {
			log.Printf("[%d] Invalid cmd length: %d", id, cmdLen)
		}
		conn.Close()
		return
	}

	// Read command
	cmdBuf := make([]byte, cmdLen)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		if verbose {
			log.Printf("[%d] Failed to read cmd: %v", id, err)
		}
		conn.Close()
		return
	}
	cmd := string(cmdBuf)

	// Clear deadline
	conn.SetDeadline(time.Time{})

	// Handle different commands
	if strings.HasPrefix(cmd, "R:") {
		// Reverse mode with SMUX: R:<listen-port>:<forward-target>
		handleReverseRegister(conn, id, cmd[2:], verbose)
	} else {
		// Forward mode: direct target address
		handleForwardConnection(conn, id, cmd, verbose)
	}
}

// handleForwardConnection handles forward mode - connect to target and relay
func handleForwardConnection(conn net.Conn, id int64, target string, verbose bool) {
	defer conn.Close()

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		if verbose {
			log.Printf("[%d] Failed to connect to %s: %v", id, target, err)
		}
		return
	}
	defer targetConn.Close()

	if verbose {
		log.Printf("[%d] Forward: client -> %s", id, target)
	}

	// Relay data
	sent, recv := relay(conn, targetConn)

	if verbose {
		log.Printf("[%d] Closed: sent=%d recv=%d", id, sent, recv)
	}
}

// smux config optimized for low latency (web browsing, interactive)
func getSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveInterval = 5 * time.Second   // Faster keepalive
	cfg.KeepAliveTimeout = 15 * time.Second   // Faster timeout detection
	cfg.MaxFrameSize = 16 * 1024              // 16KB frames (smaller = lower latency)
	cfg.MaxReceiveBuffer = 512 * 1024         // 512KB buffer (smaller for lower latency)
	cfg.MaxStreamBuffer = 256 * 1024          // 256KB per stream
	return cfg
}

// handleReverseRegister handles reverse mode registration with SMUX multiplexing
// cmd format: <listen-port>:<forward-target>
func handleReverseRegister(conn net.Conn, id int64, cmd string, verbose bool) {
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) != 2 {
		if verbose {
			log.Printf("[%d] Invalid reverse cmd: %s", id, cmd)
		}
		conn.Close()
		return
	}

	listenPort := parts[0]
	forwardAddr := parts[1]
	listenAddr := "0.0.0.0:" + listenPort

	// Check if already listening
	globalReverse.Lock()
	if _, exists := globalReverse.listeners[listenPort]; exists {
		globalReverse.Unlock()
		log.Printf("[%d] Reverse port %s already in use", id, listenPort)
		conn.Close()
		return
	}
	globalReverse.Unlock()

	// Start listener
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[%d] Failed to listen on %s: %v", id, listenAddr, err)
		conn.Close()
		return
	}

	log.Printf("[%d] Reverse tunnel: listening on %s -> client -> %s", id, listenAddr, forwardAddr)

	// Send OK to client before starting smux
	conn.Write([]byte("OK\n"))

	// Create smux session - SERVER mode (we accept streams from client)
	// Client will open streams, server accepts them
	muxSession, err := smux.Server(conn, getSmuxConfig())
	if err != nil {
		log.Printf("[%d] Failed to create smux session: %v", id, err)
		listener.Close()
		conn.Close()
		return
	}

	log.Printf("[%d] SMUX session established (multiplexed)", id)

	// Track session
	globalReverse.Lock()
	session := &reverseSession{
		listener:    listener,
		controlConn: conn,
		forwardAddr: forwardAddr,
		connQueue:   make(chan net.Conn, 100),
		verbose:     verbose,
	}
	globalReverse.listeners[listenPort] = session
	globalReverse.Unlock()

	var streamID int64

	// Accept incoming connections and relay through smux streams
	for {
		incomingConn, err := listener.Accept()
		if err != nil {
			if verbose {
				log.Printf("[%d] Reverse accept error: %v", id, err)
			}
			break
		}

		// Enable TCP_NODELAY for lower latency
		if tc, ok := incomingConn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}

		// Open smux stream to client (FAST - no new TLS handshake!)
		stream, err := muxSession.OpenStream()
		if err != nil {
			if verbose {
				log.Printf("[%d] Failed to open smux stream: %v", id, err)
			}
			incomingConn.Close()
			break
		}

		sid := atomic.AddInt64(&streamID, 1)
		if verbose {
			log.Printf("[%d] Stream %d: %s -> client -> %s", id, sid, incomingConn.RemoteAddr(), forwardAddr)
		}

		// Relay in goroutine
		go func(incoming net.Conn, stream *smux.Stream, sid int64) {
			defer incoming.Close()
			defer stream.Close()
			sent, recv := relay(incoming, stream)
			if verbose {
				log.Printf("[%d] Stream %d closed: sent=%d recv=%d", id, sid, sent, recv)
			}
		}(incomingConn, stream, sid)
	}

	// Cleanup
	globalReverse.Lock()
	delete(globalReverse.listeners, listenPort)
	globalReverse.Unlock()

	muxSession.Close()
	listener.Close()
	close(session.connQueue)

	// Drain and close any remaining connections
	for c := range session.connQueue {
		c.Close()
	}

	log.Printf("[%d] Reverse tunnel closed for port %s", id, listenPort)
}

// relayClient runs the fast relay client
func relayClient(args []string) {
	flags := flag.NewFlagSet("relay-client", flag.ContinueOnError)

	realityPubkey := flags.String("reality-pubkey", "", "")
	realityShortID := flags.String("reality-shortid", "", "")
	sni := flags.String("sni", "www.microsoft.com", "")
	tlsSkipVerify := flags.Bool("tls-skip-verify", false, "")
	noTLS := flags.Bool("no-tls", false, "")
	muxConns := flags.Int("mux", 1, "")  // Number of parallel SMUX connections
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() {
		fmt.Print(relayHelp)
		os.Exit(0)
	}
	flags.Parse(args)

	args = flags.Args()
	if len(args) < 2 {
		log.Fatal("Usage: chisel relay-client [options] <server> <local>:<remote> or R:<remote-port>:<local>")
	}

	server := args[0]
	mapping := args[1]

	// Parse Reality key
	var pubKey [32]byte
	var shortID []byte
	realityEnabled := false

	if *realityPubkey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(*realityPubkey)
		if err != nil || len(keyBytes) != 32 {
			log.Fatal("Invalid reality public key")
		}
		copy(pubKey[:], keyBytes)
		realityEnabled = true
		if *realityShortID != "" {
			shortID = []byte(*realityShortID)
		}
	}

	// Determine if server uses TLS
	useTLS := !*noTLS
	if !useTLS {
		log.Printf("relay-client: WARNING - TLS disabled, traffic NOT DPI resistant!")
	}

	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimPrefix(server, "http://")
	if !strings.Contains(server, ":") {
		if useTLS {
			server += ":443"
		} else {
			server += ":8080"
		}
	}

	// Create client config
	numMux := *muxConns
	if numMux < 1 {
		numMux = 1
	}
	if numMux > 8 {
		numMux = 8  // Max 8 parallel connections
	}

	clientCfg := &relayClientConfig{
		server:          server,
		pubKey:          pubKey,
		shortID:         shortID,
		realityEnabled:  realityEnabled,
		useTLS:          useTLS,
		tlsSkipVerify:   *tlsSkipVerify,
		sni:             *sni,
		verbose:         *verbose,
		muxConns:        numMux,
	}

	// Check if reverse mode
	if strings.HasPrefix(mapping, "R:") {
		runReverseClient(mapping[2:], clientCfg)
		return
	}

	// Forward mode - parse mapping
	parts := strings.SplitN(mapping, ":", 3)
	var localAddr, remoteAddr string

	if len(parts) == 2 {
		// local:remote (same port)
		localAddr = "0.0.0.0:" + parts[0]
		remoteAddr = "localhost:" + parts[1]
	} else if len(parts) == 3 {
		// localport:remotehost:remoteport or localip:localport:...
		if strings.Contains(parts[0], ".") {
			// localip:localport:remoteport - assume remote is localhost
			localAddr = parts[0] + ":" + parts[1]
			remoteAddr = "localhost:" + parts[2]
		} else {
			// localport:remotehost:remoteport
			localAddr = "0.0.0.0:" + parts[0]
			remoteAddr = parts[1] + ":" + parts[2]
		}
	} else {
		// Try parsing as full format: localip:localport:remotehost:remoteport
		fullParts := strings.Split(mapping, ":")
		if len(fullParts) == 4 {
			localAddr = fullParts[0] + ":" + fullParts[1]
			remoteAddr = fullParts[2] + ":" + fullParts[3]
		} else {
			log.Fatalf("Invalid mapping format: %s", mapping)
		}
	}

	log.Printf("relay-client: Forward mode")
	log.Printf("relay-client: Forwarding %s -> %s -> %s", localAddr, server, remoteAddr)
	if realityEnabled {
		log.Printf("relay-client: Reality auth enabled, SNI: %s", *sni)
	}

	// Start local listener
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", localAddr, err)
	}

	log.Printf("relay-client: Listening on %s", localAddr)

	var connID int64

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		id := atomic.AddInt64(&connID, 1)
		go handleLocalConnection(localConn, id, remoteAddr, clientCfg)
	}
}

// relayClientConfig holds client configuration
type relayClientConfig struct {
	server          string
	pubKey          [32]byte
	shortID         []byte
	realityEnabled  bool
	useTLS          bool
	tlsSkipVerify   bool
	sni             string
	verbose         bool
	muxConns        int  // Number of parallel SMUX connections
}

// runReverseClient runs the reverse mode client with SMUX multiplexing
// mapping format: <server-listen-port>:<local-host>:<local-port>
func runReverseClient(mapping string, cfg *relayClientConfig) {
	parts := strings.SplitN(mapping, ":", 3)
	if len(parts) < 2 {
		log.Fatalf("Invalid reverse mapping: %s (expected port:host:port or port:port)", mapping)
	}

	var listenPort, localAddr string
	if len(parts) == 2 {
		listenPort = parts[0]
		localAddr = "localhost:" + parts[1]
	} else {
		listenPort = parts[0]
		localAddr = parts[1] + ":" + parts[2]
	}

	log.Printf("relay-client: Reverse mode with SMUX multiplexing")
	log.Printf("relay-client: Server %s listens on :%s -> tunnel -> local %s", cfg.server, listenPort, localAddr)
	if cfg.realityEnabled {
		log.Printf("relay-client: Reality auth enabled, SNI: %s", cfg.sni)
	}

	for {
		// Connect to server
		controlConn, err := dialServer(cfg)
		if err != nil {
			log.Printf("Failed to connect: %v, retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Send reverse registration: R:<listen-port>:<forward-target>
		cmd := fmt.Sprintf("R:%s:%s", listenPort, localAddr)
		if err := sendCommand(controlConn, cmd, cfg); err != nil {
			log.Printf("Failed to send command: %v", err)
			controlConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		// Wait for OK
		buf := make([]byte, 3)
		controlConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := controlConn.Read(buf)
		if err != nil || !strings.HasPrefix(string(buf[:n]), "OK") {
			log.Printf("Failed to register reverse tunnel: %v", err)
			controlConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		controlConn.SetReadDeadline(time.Time{})

		// Create smux session - CLIENT mode (server opens streams, we accept them)
		muxSession, err := smux.Client(controlConn, getSmuxConfig())
		if err != nil {
			log.Printf("Failed to create smux session: %v", err)
			controlConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("relay-client: SMUX session established, server listening on :%s", listenPort)

		// Accept streams from server and relay to local service
		var streamID int64
		for {
			stream, err := muxSession.AcceptStream()
			if err != nil {
				if cfg.verbose {
					log.Printf("SMUX session error: %v", err)
				}
				break
			}

			sid := atomic.AddInt64(&streamID, 1)

			// Connect to local service
			go func(stream *smux.Stream, sid int64) {
				defer stream.Close()

				localConn, err := net.DialTimeout("tcp", localAddr, dialTimeout)
				if err != nil {
					if cfg.verbose {
						log.Printf("Stream %d: Failed to connect to local %s: %v", sid, localAddr, err)
					}
					return
				}
				defer localConn.Close()

				// Enable TCP_NODELAY for lower latency
				if tc, ok := localConn.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}

				if cfg.verbose {
					log.Printf("Stream %d: server -> tunnel -> %s", sid, localAddr)
				}

				sent, recv := relay(stream, localConn)

				if cfg.verbose {
					log.Printf("Stream %d: closed, sent=%d recv=%d", sid, sent, recv)
				}
			}(stream, sid)
		}

		muxSession.Close()
		log.Printf("relay-client: Connection lost, reconnecting...")
		time.Sleep(1 * time.Second)
	}
}

// dialServer creates a connection to the relay server with DPI evasion
func dialServer(cfg *relayClientConfig) (net.Conn, error) {
	var conn net.Conn
	var err error

	if cfg.useTLS {
		// Use uTLS for Chrome fingerprint (DPI evasion)
		tcpConn, err := net.DialTimeout("tcp", cfg.server, dialTimeout)
		if err != nil {
			return nil, err
		}

		// Enable TCP_NODELAY for lower latency
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}

		// Use SNI for DPI evasion - looks like connecting to legitimate site
		sni := cfg.sni
		if sni == "" {
			sni, _, _ = net.SplitHostPort(cfg.server)
		}

		utlsConfig := &utls.Config{
			ServerName:         sni,                          // SNI spoofing
			InsecureSkipVerify: cfg.tlsSkipVerify,
			NextProtos:         []string{"h2", "http/1.1"},   // ALPN - looks like HTTP/2
		}

		// Use Chrome fingerprint for maximum compatibility
		tlsConn := utls.UClient(tcpConn, utlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake failed (SNI: %s): %v", sni, err)
		}
		conn = tlsConn

		if cfg.verbose {
			log.Printf("TLS connected with SNI: %s, ALPN: h2", sni)
		}
	} else {
		// Raw TCP (not recommended - DPI can detect)
		conn, err = net.DialTimeout("tcp", cfg.server, dialTimeout)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// sendCommand sends authenticated command to server
func sendCommand(conn net.Conn, cmd string, cfg *relayClientConfig) error {
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	if cfg.realityEnabled {
		// Create Reality session
		sessionID, clientPubKey, err := reality.CreateSessionID(cfg.pubKey, cfg.shortID)
		if err != nil {
			return err
		}

		// Send auth: [2 bytes: len][32 bytes sessionID][32 bytes pubkey]
		authData := make([]byte, 64)
		copy(authData[:32], sessionID[:])
		copy(authData[32:], clientPubKey[:])

		authLen := make([]byte, 2)
		binary.BigEndian.PutUint16(authLen, uint16(len(authData)))

		if _, err := conn.Write(authLen); err != nil {
			return err
		}
		if _, err := conn.Write(authData); err != nil {
			return err
		}
	}

	// Send command: [1 byte: len][command string]
	cmdBytes := []byte(cmd)
	if len(cmdBytes) > maxTargetLen {
		return fmt.Errorf("command too long")
	}

	if _, err := conn.Write([]byte{byte(len(cmdBytes))}); err != nil {
		return err
	}
	if _, err := conn.Write(cmdBytes); err != nil {
		return err
	}

	return nil
}

func handleLocalConnection(localConn net.Conn, id int64, remoteAddr string, cfg *relayClientConfig) {
	defer localConn.Close()

	// Connect to server
	serverConn, err := dialServer(cfg)
	if err != nil {
		if cfg.verbose {
			log.Printf("[%d] Failed to connect to server: %v", id, err)
		}
		return
	}
	defer serverConn.Close()

	// Send target (forward command)
	if err := sendCommand(serverConn, remoteAddr, cfg); err != nil {
		if cfg.verbose {
			log.Printf("[%d] Failed to send command: %v", id, err)
		}
		return
	}

	if cfg.verbose {
		log.Printf("[%d] Forward: local -> %s -> %s", id, cfg.server, remoteAddr)
	}

	// Relay
	sent, recv := relay(localConn, serverConn)

	if cfg.verbose {
		log.Printf("[%d] Closed: sent=%d recv=%d", id, sent, recv)
	}
}

// closeWrite attempts to close the write side of a connection
func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}
	// For TLS connections, we can't do half-close, so just let it close fully
}

// relay copies data bidirectionally between two connections
func relay(c1, c2 net.Conn) (int64, int64) {
	var sent, recv int64
	var wg sync.WaitGroup
	wg.Add(2)

	// c1 -> c2
	go func() {
		defer wg.Done()
		n, _ := io.CopyBuffer(c2, c1, make([]byte, bufferSize))
		sent = n
		closeWrite(c2)
	}()

	// c2 -> c1
	go func() {
		defer wg.Done()
		n, _ := io.CopyBuffer(c1, c2, make([]byte, bufferSize))
		recv = n
		closeWrite(c1)
	}()

	wg.Wait()
	return sent, recv
}

// Add to main.go switch statement
func handleRelayCommand(subcmd string, args []string) bool {
	switch subcmd {
	case "relay-server":
		relayServer(args)
		return true
	case "relay-client":
		relayClient(args)
		return true
	}
	return false
}
