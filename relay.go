// Fast TCP relay with Reality authentication - NO SSH overhead
// Optimized for low latency real-time traffic (Telegram, browsing, etc.)

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
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/chisel/share/reality"
	utls "github.com/refraction-networking/utls"
)

var relayHelp = `
  Usage: chisel relay-server [options]
         chisel relay-client [options] <server> <local>:<remote>

  FAST TCP relay with Reality authentication (no SSH overhead).
  Optimized for low latency real-time traffic.

  relay-server options:
    --port, -p         Port to listen on (default: 443)
    --tls-cert         TLS certificate file (auto-generated if not provided)
    --tls-key          TLS key file (auto-generated if not provided)
    --tls-domain       Domain for auto-generated cert (default: www.microsoft.com)
    --reality-privkey  Reality private key (from 'chisel genkey')
    --reality-shortid  Reality short ID (comma-separated for rotation)
    -v                 Verbose logging

  relay-client options:
    --reality-pubkey   Reality public key
    --reality-shortid  Reality short ID
    --sni              SNI hostname to send (default: www.microsoft.com)
    --fingerprint      TLS fingerprint: chrome, firefox, safari, random (default: chrome)
    --tls-skip-verify  Skip TLS certificate verification
    -v                 Verbose logging

  Examples:
    # Server (Iran)
    chisel relay-server -p 443 --reality-privkey "..." --reality-shortid "abc123" -v

    # Client reverse mode (Germany -> Iran)
    chisel relay-client --reality-pubkey "..." --reality-shortid "abc123" \
      --sni www.google.com --tls-skip-verify \
      iran:443 R:30949:localhost:30949

    # Traffic: User -> Iran:30949 -> tunnel -> Germany:30949 (V2Ray)
`

const (
	authTimeout  = 10 * time.Second
	dialTimeout  = 5 * time.Second  // Reduced for faster failover
	copyBufSize  = 8 * 1024         // 8KB - small for low latency
	maxTargetLen = 256
)

// TLS fingerprint types
type fingerprint int

const (
	fpChrome fingerprint = iota
	fpFirefox
	fpSafari
	fpRandom
)

func parseFingerprint(s string) fingerprint {
	switch strings.ToLower(s) {
	case "firefox":
		return fpFirefox
	case "safari":
		return fpSafari
	case "random":
		return fpRandom
	default:
		return fpChrome
	}
}

func getClientHelloID(fp fingerprint) utls.ClientHelloID {
	switch fp {
	case fpFirefox:
		return utls.HelloFirefox_Auto
	case fpSafari:
		return utls.HelloSafari_Auto
	case fpRandom:
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// reverseSession tracks a reverse tunnel
type reverseSession struct {
	listener    net.Listener
	controlConn net.Conn
	localAddr   string
	done        chan struct{}
}

var (
	globalReverse = struct {
		sync.RWMutex
		sessions map[string]*reverseSession
	}{sessions: make(map[string]*reverseSession)}
)

// generateSelfSignedCert creates a self-signed certificate
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

// relayServer runs the relay server
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
	var shortIDs [][]byte
	realityEnabled := false

	if *realityPrivkey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(*realityPrivkey)
		if err != nil || len(keyBytes) != 32 {
			log.Fatal("Invalid reality private key")
		}
		copy(privKey[:], keyBytes)
		realityEnabled = true

		// Support multiple short IDs (comma-separated) for rotation
		if *realityShortID != "" {
			for _, id := range strings.Split(*realityShortID, ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					shortIDs = append(shortIDs, []byte(id))
				}
			}
		}
	}

	// Setup listener
	var listener net.Listener
	var err error
	addr := "0.0.0.0:" + *port

	if *noTLS {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (no TLS)", addr)
	} else {
		var cert tls.Certificate
		if *tlsCert != "" && *tlsKey != "" {
			cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
			if err != nil {
				log.Fatalf("Failed to load TLS cert: %v", err)
			}
		} else {
			cert, err = generateSelfSignedCert(*tlsDomain)
			if err != nil {
				log.Fatalf("Failed to generate TLS cert: %v", err)
			}
			log.Printf("relay-server: Auto-generated TLS cert for %s", *tlsDomain)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (TLS)", addr)
	}

	if realityEnabled {
		log.Printf("relay-server: Reality auth enabled, %d short ID(s)", len(shortIDs))
	}

	var connID int64
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		id := atomic.AddInt64(&connID, 1)
		go handleServerConn(conn, id, privKey, shortIDs, realityEnabled, *verbose)
	}
}

func handleServerConn(conn net.Conn, id int64, privKey [32]byte, shortIDs [][]byte, realityEnabled, verbose bool) {
	// Set TCP options for low latency
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	conn.SetDeadline(time.Now().Add(authTimeout))

	// Reality authentication
	if realityEnabled {
		authLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, authLenBuf); err != nil {
			if verbose {
				log.Printf("[%d] Auth read failed: %v", id, err)
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

		authData := make([]byte, authLen)
		if _, err := io.ReadFull(conn, authData); err != nil {
			if verbose {
				log.Printf("[%d] Auth data read failed: %v", id, err)
			}
			conn.Close()
			return
		}

		var sessionID, clientPubKey [32]byte
		copy(sessionID[:], authData[:32])
		copy(clientPubKey[:], authData[32:64])

		// Try all short IDs (supports rotation)
		authOK := false
		for _, shortID := range shortIDs {
			if err := reality.VerifySessionID(sessionID, clientPubKey, privKey, shortID); err == nil {
				authOK = true
				break
			}
		}
		// Also try with empty shortID if none matched
		if !authOK && len(shortIDs) == 0 {
			if err := reality.VerifySessionID(sessionID, clientPubKey, privKey, nil); err == nil {
				authOK = true
			}
		}

		if !authOK {
			if verbose {
				log.Printf("[%d] Reality auth failed", id)
			}
			conn.Close()
			return
		}

		if verbose {
			log.Printf("[%d] Reality auth OK", id)
		}
	}

	// Read command
	cmdLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdLenBuf); err != nil {
		conn.Close()
		return
	}

	cmdLen := int(cmdLenBuf[0])
	if cmdLen == 0 || cmdLen > maxTargetLen {
		conn.Close()
		return
	}

	cmdBuf := make([]byte, cmdLen)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		conn.Close()
		return
	}
	cmd := string(cmdBuf)

	conn.SetDeadline(time.Time{})

	if strings.HasPrefix(cmd, "R:") {
		handleReverseRegister(conn, id, cmd[2:], verbose)
	} else if strings.HasPrefix(cmd, "T:") {
		// Tunnel connection from client for reverse mode
		handleTunnelConn(conn, id, cmd[2:], verbose)
	} else {
		handleForward(conn, id, cmd, verbose)
	}
}

// handleForward connects to target and relays data
func handleForward(conn net.Conn, id int64, target string, verbose bool) {
	defer conn.Close()

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		if verbose {
			log.Printf("[%d] Dial %s failed: %v", id, target, err)
		}
		return
	}
	defer targetConn.Close()

	if tc, ok := targetConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	if verbose {
		log.Printf("[%d] Forward -> %s", id, target)
	}

	relay(conn, targetConn)
}

// handleReverseRegister sets up reverse tunnel listener
func handleReverseRegister(conn net.Conn, id int64, cmd string, verbose bool) {
	// Format: <listen-port>:<local-addr>
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) != 2 {
		log.Printf("[%d] Invalid reverse cmd: %s", id, cmd)
		conn.Close()
		return
	}

	listenPort := parts[0]
	localAddr := parts[1]
	listenAddr := "0.0.0.0:" + listenPort

	// Close existing session if any
	globalReverse.Lock()
	if old, exists := globalReverse.sessions[listenPort]; exists {
		log.Printf("[%d] Replacing session on port %s", id, listenPort)
		close(old.done)
		old.listener.Close()
		old.controlConn.Close()
		delete(globalReverse.sessions, listenPort)
	}
	globalReverse.Unlock()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[%d] Listen %s failed: %v", id, listenAddr, err)
		conn.Close()
		return
	}

	log.Printf("[%d] Reverse: :%s -> tunnel -> %s", id, listenPort, localAddr)

	// Send OK
	conn.Write([]byte("OK"))

	session := &reverseSession{
		listener:    listener,
		controlConn: conn,
		localAddr:   localAddr,
		done:        make(chan struct{}),
	}

	globalReverse.Lock()
	globalReverse.sessions[listenPort] = session
	globalReverse.Unlock()

	// Handle incoming connections
	go func() {
		for {
			select {
			case <-session.done:
				return
			default:
			}

			listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
			inConn, err := listener.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				if verbose {
					log.Printf("[%d] Accept error: %v", id, err)
				}
				break
			}

			// Request new tunnel connection from client
			// Send signal: "NEW:<local-addr>\n"
			signal := fmt.Sprintf("NEW:%s\n", localAddr)
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte(signal))
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				if verbose {
					log.Printf("[%d] Signal write failed: %v", id, err)
				}
				inConn.Close()
				break
			}

			// Wait for client to connect back with tunnel
			// Store incoming connection for matching
			go waitForTunnelAndRelay(inConn, session, verbose)
		}

		// Cleanup
		globalReverse.Lock()
		delete(globalReverse.sessions, listenPort)
		globalReverse.Unlock()
		listener.Close()
		conn.Close()
		log.Printf("[%d] Reverse tunnel closed for port %s", id, listenPort)
	}()

	// Read signals from control connection (keepalive)
	buf := make([]byte, 64)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}

	close(session.done)
}

// Pending connections waiting for tunnel - FIFO queue per localAddr
var pendingConns = struct {
	sync.Mutex
	queues map[string][]chan net.Conn
}{queues: make(map[string][]chan net.Conn)}

func waitForTunnelAndRelay(inConn net.Conn, session *reverseSession, verbose bool) {
	ch := make(chan net.Conn, 1)

	// Add to queue for this localAddr
	pendingConns.Lock()
	pendingConns.queues[session.localAddr] = append(pendingConns.queues[session.localAddr], ch)
	pendingConns.Unlock()

	// Wait for tunnel connection
	select {
	case tunnelConn := <-ch:
		if tc, ok := inConn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		if verbose {
			log.Printf("Relaying: incoming <-> tunnel -> %s", session.localAddr)
		}
		relay(inConn, tunnelConn)
	case <-time.After(10 * time.Second):
		if verbose {
			log.Printf("Tunnel timeout for %s", session.localAddr)
		}
		inConn.Close()
	case <-session.done:
		inConn.Close()
	}
}

// handleTunnelConn handles a tunnel connection from client (T: prefix)
func handleTunnelConn(conn net.Conn, id int64, localAddr string, verbose bool) {
	// Find pending connection for this localAddr
	pendingConns.Lock()
	queue := pendingConns.queues[localAddr]
	if len(queue) > 0 {
		// Pop first waiting channel (FIFO)
		ch := queue[0]
		pendingConns.queues[localAddr] = queue[1:]
		pendingConns.Unlock()

		// Send this tunnel connection to the waiting goroutine
		ch <- conn
		if verbose {
			log.Printf("[%d] Tunnel matched for %s", id, localAddr)
		}
		return
	}
	pendingConns.Unlock()

	// No pending connection - close
	if verbose {
		log.Printf("[%d] No pending conn for tunnel %s", id, localAddr)
	}
	conn.Close()
}

// relayClient runs the relay client
func relayClient(args []string) {
	flags := flag.NewFlagSet("relay-client", flag.ContinueOnError)

	realityPubkey := flags.String("reality-pubkey", "", "")
	realityShortID := flags.String("reality-shortid", "", "")
	sni := flags.String("sni", "www.microsoft.com", "")
	fpStr := flags.String("fingerprint", "chrome", "")
	tlsSkipVerify := flags.Bool("tls-skip-verify", false, "")
	noTLS := flags.Bool("no-tls", false, "")
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() {
		fmt.Print(relayHelp)
		os.Exit(0)
	}
	flags.Parse(args)

	args = flags.Args()
	if len(args) < 2 {
		log.Fatal("Usage: chisel relay-client [options] <server> <mapping>")
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

	fp := parseFingerprint(*fpStr)
	useTLS := !*noTLS

	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimPrefix(server, "http://")
	if !strings.Contains(server, ":") {
		if useTLS {
			server += ":443"
		} else {
			server += ":8080"
		}
	}

	cfg := &clientConfig{
		server:         server,
		pubKey:         pubKey,
		shortID:        shortID,
		realityEnabled: realityEnabled,
		useTLS:         useTLS,
		tlsSkipVerify:  *tlsSkipVerify,
		sni:            *sni,
		fingerprint:    fp,
		verbose:        *verbose,
	}

	if strings.HasPrefix(mapping, "R:") {
		runReverseClient(mapping[2:], cfg)
	} else {
		runForwardClient(mapping, cfg)
	}
}

type clientConfig struct {
	server         string
	pubKey         [32]byte
	shortID        []byte
	realityEnabled bool
	useTLS         bool
	tlsSkipVerify  bool
	sni            string
	fingerprint    fingerprint
	verbose        bool
}

func runForwardClient(mapping string, cfg *clientConfig) {
	parts := strings.SplitN(mapping, ":", 3)
	var localAddr, remoteAddr string

	if len(parts) == 2 {
		localAddr = "0.0.0.0:" + parts[0]
		remoteAddr = "localhost:" + parts[1]
	} else if len(parts) == 3 {
		localAddr = "0.0.0.0:" + parts[0]
		remoteAddr = parts[1] + ":" + parts[2]
	} else {
		log.Fatalf("Invalid mapping: %s", mapping)
	}

	log.Printf("relay-client: Forward %s -> %s -> %s", localAddr, cfg.server, remoteAddr)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	var connID int64
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		id := atomic.AddInt64(&connID, 1)
		go handleForwardClient(conn, id, remoteAddr, cfg)
	}
}

func handleForwardClient(localConn net.Conn, id int64, remoteAddr string, cfg *clientConfig) {
	defer localConn.Close()

	serverConn, err := dialServer(cfg)
	if err != nil {
		if cfg.verbose {
			log.Printf("[%d] Dial server failed: %v", id, err)
		}
		return
	}
	defer serverConn.Close()

	if err := sendAuth(serverConn, remoteAddr, cfg); err != nil {
		if cfg.verbose {
			log.Printf("[%d] Auth failed: %v", id, err)
		}
		return
	}

	if cfg.verbose {
		log.Printf("[%d] Forward -> %s", id, remoteAddr)
	}

	relay(localConn, serverConn)
}

func runReverseClient(mapping string, cfg *clientConfig) {
	parts := strings.SplitN(mapping, ":", 3)
	var listenPort, localAddr string

	if len(parts) == 2 {
		listenPort = parts[0]
		localAddr = "localhost:" + parts[1]
	} else if len(parts) == 3 {
		listenPort = parts[0]
		localAddr = parts[1] + ":" + parts[2]
	} else {
		log.Fatalf("Invalid mapping: %s", mapping)
	}

	log.Printf("relay-client: Reverse mode")
	log.Printf("relay-client: Server :%s -> tunnel -> local %s", listenPort, localAddr)

	for {
		if err := runReverseSession(listenPort, localAddr, cfg); err != nil {
			log.Printf("Session error: %v, reconnecting in 3s...", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func runReverseSession(listenPort, localAddr string, cfg *clientConfig) error {
	// Connect control channel
	controlConn, err := dialServer(cfg)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}

	// Register reverse tunnel
	cmd := fmt.Sprintf("R:%s:%s", listenPort, localAddr)
	if err := sendAuth(controlConn, cmd, cfg); err != nil {
		controlConn.Close()
		return fmt.Errorf("auth failed: %v", err)
	}

	// Wait for OK
	buf := make([]byte, 2)
	controlConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := controlConn.Read(buf)
	controlConn.SetReadDeadline(time.Time{})
	if err != nil || string(buf[:n]) != "OK" {
		controlConn.Close()
		return fmt.Errorf("registration failed")
	}

	log.Printf("relay-client: Connected, server listening on :%s", listenPort)

	// Read signals from server
	reader := make([]byte, 256)
	for {
		controlConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, err := controlConn.Read(reader)
		if err != nil {
			return fmt.Errorf("control read: %v", err)
		}

		// Parse signal
		signal := string(reader[:n])
		lines := strings.Split(signal, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "NEW:") {
				target := strings.TrimPrefix(line, "NEW:")
				go handleNewTunnel(target, cfg)
			}
		}

		// Send keepalive
		controlConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		controlConn.Write([]byte("K"))
		controlConn.SetWriteDeadline(time.Time{})
	}
}

func handleNewTunnel(localAddr string, cfg *clientConfig) {
	// Connect to server for new tunnel
	tunnelConn, err := dialServer(cfg)
	if err != nil {
		if cfg.verbose {
			log.Printf("Tunnel dial failed: %v", err)
		}
		return
	}

	// Send tunnel marker (T: prefix means this is a tunnel connection)
	cmd := fmt.Sprintf("T:%s", localAddr)
	if err := sendAuth(tunnelConn, cmd, cfg); err != nil {
		tunnelConn.Close()
		return
	}

	// Connect to local service
	localConn, err := net.DialTimeout("tcp", localAddr, dialTimeout)
	if err != nil {
		if cfg.verbose {
			log.Printf("Local dial %s failed: %v", localAddr, err)
		}
		tunnelConn.Close()
		return
	}

	if tc, ok := localConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	if cfg.verbose {
		log.Printf("Tunnel: server -> %s", localAddr)
	}

	relay(tunnelConn, localConn)
}

func dialServer(cfg *clientConfig) (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", cfg.server, dialTimeout)
	if err != nil {
		return nil, err
	}

	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	if !cfg.useTLS {
		return tcpConn, nil
	}

	// Use uTLS with fingerprint
	sni := cfg.sni
	if sni == "" {
		sni, _, _ = net.SplitHostPort(cfg.server)
	}

	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg.tlsSkipVerify,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	helloID := getClientHelloID(cfg.fingerprint)
	tlsConn := utls.UClient(tcpConn, utlsConfig, helloID)

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	if cfg.verbose {
		log.Printf("TLS connected: SNI=%s", sni)
	}

	return tlsConn, nil
}

func sendAuth(conn net.Conn, cmd string, cfg *clientConfig) error {
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	if cfg.realityEnabled {
		sessionID, clientPubKey, err := reality.CreateSessionID(cfg.pubKey, cfg.shortID)
		if err != nil {
			return err
		}

		authData := make([]byte, 64)
		copy(authData[:32], sessionID[:])
		copy(authData[32:], clientPubKey[:])

		authLen := make([]byte, 2)
		binary.BigEndian.PutUint16(authLen, 64)

		if _, err := conn.Write(authLen); err != nil {
			return err
		}
		if _, err := conn.Write(authData); err != nil {
			return err
		}
	}

	cmdBytes := []byte(cmd)
	if _, err := conn.Write([]byte{byte(len(cmdBytes))}); err != nil {
		return err
	}
	if _, err := conn.Write(cmdBytes); err != nil {
		return err
	}

	return nil
}

// relay copies data bidirectionally with low latency
func relay(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, copyBufSize)
		for {
			src.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, werr := dst.Write(buf[:n])
				if werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Half-close
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(c1, c2)
	go copy(c2, c1)

	wg.Wait()
	c1.Close()
	c2.Close()
}

// Fingerprint rotation (call periodically to change fingerprint)
var currentFingerprint = fpChrome

func rotateFingerprint() fingerprint {
	fps := []fingerprint{fpChrome, fpFirefox, fpSafari}
	currentFingerprint = fps[mrand.Intn(len(fps))]
	return currentFingerprint
}

// For main.go
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
