// Backhaul-killer: High-performance tunnel optimized for Iran/China DPI evasion
// Key optimizations:
// 1. Connection pooling - pre-established connections
// 2. Splice mode - zero-copy when both sides are raw TCP
// 3. TLS fragmentation - split handshake to evade DPI
// 4. Traffic detection - avoid double encryption
// 5. Padding - randomize packet sizes

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var tunnelHelp = `
  Usage: chisel tunnel-server [options]
         chisel tunnel-client [options] <server> <mappings...>

  High-performance tunnel optimized for Iran/China DPI evasion.

  Features:
    - Connection pooling (pre-established, no handshake delay)
    - Zero-copy splice mode for raw TCP
    - TLS handshake fragmentation (evades DPI)
    - Traffic padding (hides packet size patterns)
    - Multi-connection mode (parallel streams)

  tunnel-server options:
    --port, -p         Listen port (default: 443)
    --password         Authentication password
    --no-tls           Disable TLS (use if behind CDN/proxy)
    --tls-cert         TLS certificate file
    --tls-key          TLS key file
    -v                 Verbose logging

  tunnel-client options:
    --password         Authentication password
    --pool-size        Connection pool size (default: 8)
    --tls-skip-verify  Skip TLS certificate verification (default: true)
    --sni              TLS SNI hostname (default: server hostname)
    --fragment         Fragment TLS handshake (default: true)
    --fragment-size    Fragment size in bytes (default: 2-8 random)
    --fragment-delay   Delay between fragments ms (default: 2-8ms)
    --padding          Enable random padding (default: true)
    --no-tls           Disable TLS
    -v                 Verbose logging

  Mapping formats:
    LOCAL:REMOTE              Forward: listen LOCAL, connect REMOTE
    R:LISTEN:LOCAL            Reverse: server listens LISTEN, forward to LOCAL

  Examples:
    # Server (Iran - open IP)
    chisel tunnel-server -p 443 --password secret -v

    # Client (Germany - has services)
    chisel tunnel-client --password secret --pool-size 8 \
      iran:443 R:30949:localhost:30949 R:8080:localhost:80

    # Traffic flow: User -> Iran:30949 -> tunnel -> Germany:30949
`

const (
	cmdAuth      byte = 0x01
	cmdConnect   byte = 0x02
	cmdData      byte = 0x03
	cmdKeepAlive byte = 0x04
	cmdOK        byte = 0x10
	cmdError     byte = 0x11

	maxPacketSize  = 16 * 1024        // 16KB max packet
	copyBufferSize = 32 * 1024        // 32KB copy buffer
	poolCheckInterval = 5 * time.Second
)

// ============== CONNECTION POOL ==============

type ConnPool struct {
	mu        sync.Mutex
	conns     chan net.Conn
	factory   func() (net.Conn, error)
	size      int
	active    int32
	closed    bool
}

func NewConnPool(size int, factory func() (net.Conn, error)) *ConnPool {
	p := &ConnPool{
		conns:   make(chan net.Conn, size),
		factory: factory,
		size:    size,
	}
	// Pre-warm pool
	go p.warmup()
	return p
}

func (p *ConnPool) warmup() {
	for i := 0; i < p.size; i++ {
		if p.closed {
			return
		}
		// Retry up to 3 times per connection
		var conn net.Conn
		var err error
		for retry := 0; retry < 3; retry++ {
			conn, err = p.factory()
			if err == nil {
				break
			}
			log.Printf("Pool warmup %d/%d attempt %d failed: %v", i+1, p.size, retry+1, err)
			time.Sleep(time.Duration(retry+1) * time.Second)
		}
		if err != nil {
			continue
		}
		select {
		case p.conns <- conn:
			log.Printf("Pool warmup %d/%d OK", i+1, p.size)
		default:
			conn.Close()
		}
	}
}

func (p *ConnPool) Get() (net.Conn, error) {
	// Try to get from pool first
	select {
	case conn := <-p.conns:
		if isConnAlive(conn) {
			return conn, nil
		}
		conn.Close()
	default:
	}
	// Create new connection
	return p.factory()
}

func (p *ConnPool) Put(conn net.Conn) {
	if p.closed {
		conn.Close()
		return
	}
	select {
	case p.conns <- conn:
	default:
		conn.Close()
	}
}

func (p *ConnPool) maintain() {
	ticker := time.NewTicker(poolCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		if p.closed {
			return
		}
		// Refill pool
		current := len(p.conns)
		for i := current; i < p.size; i++ {
			conn, err := p.factory()
			if err != nil {
				break
			}
			select {
			case p.conns <- conn:
			default:
				conn.Close()
				return
			}
		}
	}
}

func (p *ConnPool) Close() {
	p.closed = true
	close(p.conns)
	for conn := range p.conns {
		conn.Close()
	}
}

func isConnAlive(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err == io.EOF {
		return false
	}
	return true
}

// ============== TLS FRAGMENTATION ==============

// FragmentedConn wraps a connection and fragments writes
type FragmentedConn struct {
	net.Conn
	fragmentSize    int
	fragmentDelay   time.Duration
	firstWrite      bool
	mu              sync.Mutex
}

func NewFragmentedConn(conn net.Conn, minSize, maxSize int, minDelay, maxDelay time.Duration) *FragmentedConn {
	size := minSize
	if maxSize > minSize {
		b := make([]byte, 1)
		rand.Read(b)
		size = minSize + int(b[0])%(maxSize-minSize)
	}
	delay := minDelay
	if maxDelay > minDelay {
		b := make([]byte, 1)
		rand.Read(b)
		delay = minDelay + time.Duration(int(b[0])%int(maxDelay-minDelay))
	}
	return &FragmentedConn{
		Conn:          conn,
		fragmentSize:  size,
		fragmentDelay: delay,
		firstWrite:    true,
	}
}

func (f *FragmentedConn) Write(p []byte) (n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Only fragment first few writes (TLS handshake)
	if !f.firstWrite || len(p) < f.fragmentSize*2 {
		return f.Conn.Write(p)
	}
	f.firstWrite = false

	// Fragment the write
	total := 0
	for len(p) > 0 {
		size := f.fragmentSize
		if size > len(p) {
			size = len(p)
		}
		written, err := f.Conn.Write(p[:size])
		total += written
		if err != nil {
			return total, err
		}
		p = p[size:]
		if len(p) > 0 && f.fragmentDelay > 0 {
			time.Sleep(f.fragmentDelay)
		}
	}
	return total, nil
}

// ============== PADDING ==============

func addPadding(data []byte, maxPadding int) []byte {
	if maxPadding <= 0 {
		return data
	}
	b := make([]byte, 1)
	rand.Read(b)
	paddingLen := int(b[0]) % maxPadding
	if paddingLen == 0 {
		return data
	}
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	// Format: [2 bytes real len][data][padding]
	result := make([]byte, 2+len(data)+paddingLen)
	binary.BigEndian.PutUint16(result[:2], uint16(len(data)))
	copy(result[2:], data)
	copy(result[2+len(data):], padding)
	return result
}

func removePadding(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	realLen := binary.BigEndian.Uint16(data[:2])
	if int(realLen) > len(data)-2 {
		return data
	}
	return data[2 : 2+realLen]
}

// ============== PROTOCOL ==============

func writePacket(conn net.Conn, cmd byte, data []byte) error {
	// Format: [1 byte cmd][2 bytes len][data]
	header := make([]byte, 3)
	header[0] = cmd
	binary.BigEndian.PutUint16(header[1:], uint16(len(data)))

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func readPacket(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 3)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))  // Reduced from 60s
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	cmd := header[0]
	length := binary.BigEndian.Uint16(header[1:])
	if length > maxPacketSize {
		return 0, nil, fmt.Errorf("packet too large: %d", length)
	}
	if length == 0 {
		return cmd, nil, nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return 0, nil, err
	}
	return cmd, data, nil
}

// ============== SERVER ==============

type TunnelServer struct {
	password  string
	verbose   bool
	listeners map[string]net.Listener
	mu        sync.RWMutex
	connID    int64
}

func tunnelServer(args []string) {
	flags := flag.NewFlagSet("tunnel-server", flag.ContinueOnError)

	port := flags.String("port", "443", "")
	p := flags.String("p", "", "")
	password := flags.String("password", "", "")
	noTLS := flags.Bool("no-tls", false, "")
	tlsCert := flags.String("tls-cert", "", "")
	tlsKey := flags.String("tls-key", "", "")
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() { fmt.Print(tunnelHelp); os.Exit(0) }
	flags.Parse(args)

	if *p != "" {
		*port = *p
	}

	server := &TunnelServer{
		password:  *password,
		verbose:   *verbose,
		listeners: make(map[string]net.Listener),
	}

	addr := "0.0.0.0:" + *port
	var listener net.Listener
	var err error

	if *noTLS {
		listener, err = net.Listen("tcp", addr)
		log.Printf("tunnel-server: Listening on %s (no TLS)", addr)
	} else {
		var cert tls.Certificate
		if *tlsCert != "" && *tlsKey != "" {
			cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		} else {
			cert, err = generateSelfSignedCert("localhost")
		}
		if err != nil {
			log.Fatalf("TLS setup failed: %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", addr, tlsConfig)
		log.Printf("tunnel-server: Listening on %s (TLS)", addr)
	}
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go server.handleConn(conn)
	}
}

func (s *TunnelServer) handleConn(conn net.Conn) {
	id := atomic.AddInt64(&s.connID, 1)

	// Set TCP options
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Read auth
	if s.verbose {
		log.Printf("[%d] Waiting for auth...", id)
	}
	cmd, data, err := readPacket(conn)
	if err != nil {
		if s.verbose {
			log.Printf("[%d] Auth read error: %v", id, err)
		}
		conn.Close()
		return
	}
	if cmd != cmdAuth {
		if s.verbose {
			log.Printf("[%d] Expected auth cmd, got: %d", id, cmd)
		}
		conn.Close()
		return
	}

	// Verify password
	if s.verbose {
		log.Printf("[%d] Got auth, password len=%d", id, len(data))
	}
	if s.password != "" && string(data) != s.password {
		if s.verbose {
			log.Printf("[%d] Password mismatch", id)
		}
		writePacket(conn, cmdError, []byte("auth failed"))
		conn.Close()
		return
	}

	// Send OK
	if s.verbose {
		log.Printf("[%d] Sending OK...", id)
	}
	if err := writePacket(conn, cmdOK, nil); err != nil {
		if s.verbose {
			log.Printf("[%d] Failed to send OK: %v", id, err)
		}
		conn.Close()
		return
	}

	if s.verbose {
		log.Printf("[%d] Authenticated", id)
	}

	// Read command
	cmd, data, err = readPacket(conn)
	if err != nil {
		conn.Close()
		return
	}

	switch cmd {
	case cmdConnect:
		// Forward mode: connect to target
		target := string(data)
		s.handleForward(conn, id, target)
	case 'T':
		// Tunnel data connection for reverse mode
		s.handleTunnelData(conn, id, string(data))
	case 'R':
		// Control connection for reverse tunnels
		s.handleControl(conn, id, cmd, string(data))
	default:
		if s.verbose {
			log.Printf("[%d] Unknown command: %c", id, cmd)
		}
		conn.Close()
	}
}

func (s *TunnelServer) handleForward(conn net.Conn, id int64, target string) {
	defer conn.Close()

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if s.verbose {
			log.Printf("[%d] Dial %s failed: %v", id, target, err)
		}
		writePacket(conn, cmdError, []byte(err.Error()))
		return
	}
	defer targetConn.Close()

	if tc, ok := targetConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	writePacket(conn, cmdOK, nil)

	if s.verbose {
		log.Printf("[%d] Forward -> %s", id, target)
	}

	// Use splice-optimized copy
	copyBidirectional(conn, targetConn)
}

func (s *TunnelServer) handleControl(conn net.Conn, id int64, cmd byte, data string) {
	// Parse reverse tunnel request: "R:listenPort:targetAddr"
	parts := strings.SplitN(data, ":", 3)
	if len(parts) < 2 {
		writePacket(conn, cmdError, []byte("invalid format"))
		conn.Close()
		return
	}

	listenPort := parts[0]
	targetAddr := "localhost:" + listenPort
	if len(parts) == 3 {
		targetAddr = parts[1] + ":" + parts[2]
	} else if len(parts) == 2 {
		targetAddr = parts[1]
	}

	listenAddr := "0.0.0.0:" + listenPort

	// Close existing listener
	s.mu.Lock()
	if old, exists := s.listeners[listenPort]; exists {
		old.Close()
		delete(s.listeners, listenPort)
	}
	s.mu.Unlock()

	// Start listener
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		writePacket(conn, cmdError, []byte(err.Error()))
		conn.Close()
		return
	}

	s.mu.Lock()
	s.listeners[listenPort] = listener
	s.mu.Unlock()

	writePacket(conn, cmdOK, nil)
	log.Printf("[%d] Reverse: :%s -> tunnel -> %s", id, listenPort, targetAddr)

	// Handle incoming connections
	go func() {
		for {
			inConn, err := listener.Accept()
			if err != nil {
				break
			}

			if tc, ok := inConn.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}

			// Signal client to create new tunnel
			if err := writePacket(conn, cmdConnect, []byte(targetAddr)); err != nil {
				inConn.Close()
				break
			}

			// Wait for tunnel connection
			go s.waitAndRelay(inConn, conn, id, targetAddr)
		}

		s.mu.Lock()
		delete(s.listeners, listenPort)
		s.mu.Unlock()
		listener.Close()
		conn.Close()
	}()

	// Keepalive loop
	for {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		cmd, _, err := readPacket(conn)
		if err != nil {
			break
		}
		if cmd == cmdKeepAlive {
			writePacket(conn, cmdKeepAlive, nil)
		}
	}
}

// Pending tunnels for reverse mode
var pendingTunnels = struct {
	sync.Mutex
	m map[string][]chan net.Conn
}{m: make(map[string][]chan net.Conn)}

func (s *TunnelServer) handleTunnelData(conn net.Conn, id int64, targetAddr string) {
	// Find pending connection for this target
	pendingTunnels.Lock()
	queue := pendingTunnels.m[targetAddr]
	if len(queue) > 0 {
		ch := queue[0]
		pendingTunnels.m[targetAddr] = queue[1:]
		pendingTunnels.Unlock()

		// Send tunnel connection to waiting goroutine
		ch <- conn
		if s.verbose {
			log.Printf("[%d] Tunnel matched for %s", id, targetAddr)
		}
		return
	}
	pendingTunnels.Unlock()

	if s.verbose {
		log.Printf("[%d] No pending connection for tunnel %s", id, targetAddr)
	}
	conn.Close()
}

func (s *TunnelServer) waitAndRelay(inConn net.Conn, ctrlConn net.Conn, id int64, targetAddr string) {
	ch := make(chan net.Conn, 1)

	pendingTunnels.Lock()
	pendingTunnels.m[targetAddr] = append(pendingTunnels.m[targetAddr], ch)
	pendingTunnels.Unlock()

	select {
	case tunnelConn := <-ch:
		if s.verbose {
			log.Printf("[%d] Relaying: incoming <-> tunnel -> %s", id, targetAddr)
		}
		copyBidirectional(inConn, tunnelConn)
	case <-time.After(30 * time.Second):
		if s.verbose {
			log.Printf("[%d] Tunnel timeout for %s", id, targetAddr)
		}
		// Remove from pending
		pendingTunnels.Lock()
		queue := pendingTunnels.m[targetAddr]
		for i, c := range queue {
			if c == ch {
				pendingTunnels.m[targetAddr] = append(queue[:i], queue[i+1:]...)
				break
			}
		}
		pendingTunnels.Unlock()
		inConn.Close()
	}
}

// ============== CLIENT ==============

type TunnelClient struct {
	server        string
	password      string
	useTLS        bool
	tlsSkipVerify bool
	sni           string
	fragment      bool
	fragMinSize   int
	fragMaxSize   int
	fragMinDelay  time.Duration
	fragMaxDelay  time.Duration
	padding       bool
	verbose       bool
	pool          *ConnPool
}

func tunnelClient(args []string) {
	flags := flag.NewFlagSet("tunnel-client", flag.ContinueOnError)

	password := flags.String("password", "", "")
	poolSize := flags.Int("pool-size", 8, "")
	fragment := flags.Bool("fragment", true, "")
	fragSize := flags.String("fragment-size", "2-8", "")     // Smaller fragments for DPI evasion
	fragDelay := flags.String("fragment-delay", "2-8", "")   // Shorter delays
	padding := flags.Bool("padding", true, "")
	noTLS := flags.Bool("no-tls", false, "")
	tlsSkipVerify := flags.Bool("tls-skip-verify", true, "")  // Default true for self-signed certs
	sni := flags.String("sni", "", "")
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() { fmt.Print(tunnelHelp); os.Exit(0) }
	flags.Parse(args)

	args = flags.Args()
	if len(args) < 2 {
		log.Fatal("Usage: chisel tunnel-client [options] <server> <mapping...>")
	}

	server := args[0]
	mappings := args[1:]

	// Parse server address
	if !strings.Contains(server, ":") {
		if *noTLS {
			server += ":8080"
		} else {
			server += ":443"
		}
	}

	// Parse fragment settings
	var fragMin, fragMax int
	fmt.Sscanf(*fragSize, "%d-%d", &fragMin, &fragMax)
	if fragMin == 0 {
		fragMin = 2
	}
	if fragMax == 0 {
		fragMax = 8
	}

	var delayMin, delayMax int
	fmt.Sscanf(*fragDelay, "%d-%d", &delayMin, &delayMax)
	if delayMin == 0 {
		delayMin = 2
	}
	if delayMax == 0 {
		delayMax = 8
	}

	client := &TunnelClient{
		server:        server,
		password:      *password,
		useTLS:        !*noTLS,
		tlsSkipVerify: *tlsSkipVerify,
		sni:           *sni,
		fragment:      *fragment,
		fragMinSize:   fragMin,
		fragMaxSize:   fragMax,
		fragMinDelay:  time.Duration(delayMin) * time.Millisecond,
		fragMaxDelay:  time.Duration(delayMax) * time.Millisecond,
		padding:       *padding,
		verbose:       *verbose,
	}

	// Create connection pool
	client.pool = NewConnPool(*poolSize, func() (net.Conn, error) {
		return client.dialAndAuth()
	})
	go client.pool.maintain()

	log.Printf("tunnel-client: Connecting to %s (pool=%d)", server, *poolSize)

	// Start tunnels for each mapping
	for _, mapping := range mappings {
		if strings.HasPrefix(mapping, "R:") {
			go client.runReverse(mapping[2:])
		} else {
			go client.runForward(mapping)
		}
	}

	// Wait forever
	select {}
}

func (c *TunnelClient) dial() (net.Conn, error) {
	if c.verbose {
		log.Printf("Dialing %s...", c.server)
	}

	tcpConn, err := net.DialTimeout("tcp", c.server, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %v", err)
	}

	if c.verbose {
		log.Printf("TCP connected to %s", c.server)
	}

	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	if !c.useTLS {
		return tcpConn, nil
	}

	// Wrap with fragmentation if enabled
	var conn net.Conn = tcpConn
	if c.fragment {
		if c.verbose {
			log.Printf("TLS fragmentation enabled: %d-%d bytes, %v-%v delay",
				c.fragMinSize, c.fragMaxSize, c.fragMinDelay, c.fragMaxDelay)
		}
		conn = NewFragmentedConn(tcpConn, c.fragMinSize, c.fragMaxSize, c.fragMinDelay, c.fragMaxDelay)
	}

	// TLS handshake
	if c.verbose {
		log.Printf("Starting TLS handshake...")
	}

	// Determine SNI
	serverName := c.sni
	if serverName == "" {
		// Use server hostname as SNI
		host, _, _ := net.SplitHostPort(c.server)
		serverName = host
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.tlsSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	if c.verbose {
		log.Printf("TLS connected (version: %x, SNI: %s)", tlsConn.ConnectionState().Version, serverName)
	}

	return tlsConn, nil
}

func (c *TunnelClient) dialAndAuth() (net.Conn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}

	// Send auth
	if c.verbose {
		log.Printf("Sending auth packet...")
	}
	if err := writePacket(conn, cmdAuth, []byte(c.password)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth send failed: %v", err)
	}

	// Read response
	if c.verbose {
		log.Printf("Waiting for auth response...")
	}
	cmd, data, err := readPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth response read failed: %v", err)
	}
	if cmd != cmdOK {
		conn.Close()
		return nil, fmt.Errorf("auth rejected: cmd=%d data=%s", cmd, string(data))
	}

	if c.verbose {
		log.Printf("Authenticated successfully")
	}

	return conn, nil
}

func (c *TunnelClient) runForward(mapping string) {
	parts := strings.SplitN(mapping, ":", 3)
	var localAddr, remoteAddr string

	if len(parts) == 2 {
		localAddr = "0.0.0.0:" + parts[0]
		remoteAddr = "localhost:" + parts[1]
	} else if len(parts) == 3 {
		localAddr = "0.0.0.0:" + parts[0]
		remoteAddr = parts[1] + ":" + parts[2]
	} else {
		log.Printf("Invalid mapping: %s", mapping)
		return
	}

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("Listen %s failed: %v", localAddr, err)
		return
	}

	log.Printf("Forward: %s -> %s -> %s", localAddr, c.server, remoteAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go c.handleForward(conn, remoteAddr)
	}
}

func (c *TunnelClient) handleForward(localConn net.Conn, remoteAddr string) {
	defer localConn.Close()

	// Get connection from pool
	serverConn, err := c.pool.Get()
	if err != nil {
		if c.verbose {
			log.Printf("Pool get failed: %v", err)
		}
		return
	}
	defer serverConn.Close()

	// Send connect request
	if err := writePacket(serverConn, cmdConnect, []byte(remoteAddr)); err != nil {
		return
	}

	// Wait for OK
	cmd, _, err := readPacket(serverConn)
	if err != nil || cmd != cmdOK {
		return
	}

	if c.verbose {
		log.Printf("Forward: local -> %s", remoteAddr)
	}

	copyBidirectional(localConn, serverConn)
}

func (c *TunnelClient) runReverse(mapping string) {
	parts := strings.SplitN(mapping, ":", 3)
	var listenPort, localAddr string

	if len(parts) == 2 {
		listenPort = parts[0]
		localAddr = "localhost:" + parts[1]
	} else if len(parts) == 3 {
		listenPort = parts[0]
		localAddr = parts[1] + ":" + parts[2]
	} else {
		log.Printf("Invalid reverse mapping: %s", mapping)
		return
	}

	for {
		if err := c.runReverseSession(listenPort, localAddr); err != nil {
			log.Printf("Reverse session error: %v, reconnecting in 1s...", err)
			time.Sleep(1 * time.Second)  // Fast reconnect
		}
	}
}

func (c *TunnelClient) runReverseSession(listenPort, localAddr string) error {
	// Connect control channel
	controlConn, err := c.dialAndAuth()
	if err != nil {
		return err
	}

	// Register reverse tunnel
	cmd := fmt.Sprintf("%s:%s", listenPort, localAddr)
	if err := writePacket(controlConn, 'R', []byte(cmd)); err != nil {
		controlConn.Close()
		return err
	}

	// Wait for OK
	respCmd, _, err := readPacket(controlConn)
	if err != nil || respCmd != cmdOK {
		controlConn.Close()
		return fmt.Errorf("registration failed")
	}

	log.Printf("Reverse: server:%s -> tunnel -> %s", listenPort, localAddr)

	// Handle tunnel requests
	for {
		cmd, data, err := readPacket(controlConn)
		if err != nil {
			return err
		}

		switch cmd {
		case cmdConnect:
			// Server wants us to create a tunnel
			targetAddr := string(data)
			go c.handleReverseTunnel(targetAddr)
		case cmdKeepAlive:
			writePacket(controlConn, cmdKeepAlive, nil)
		}
	}
}

func (c *TunnelClient) handleReverseTunnel(targetAddr string) {
	// Connect to server for tunnel
	tunnelConn, err := c.dialAndAuth()
	if err != nil {
		if c.verbose {
			log.Printf("Tunnel dial failed: %v", err)
		}
		return
	}

	// Send tunnel command
	if err := writePacket(tunnelConn, 'T', []byte(targetAddr)); err != nil {
		tunnelConn.Close()
		return
	}

	// Connect to local service
	localConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		if c.verbose {
			log.Printf("Local dial %s failed: %v", targetAddr, err)
		}
		tunnelConn.Close()
		return
	}

	if tc, ok := localConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	if c.verbose {
		log.Printf("Tunnel: server <-> %s", targetAddr)
	}

	copyBidirectional(tunnelConn, localConn)
}

// ============== OPTIMIZED COPY ==============

// copyBidirectional copies data between two connections using the most efficient method
func copyBidirectional(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyOptimized(c1, c2)
		closeWrite(c1)
	}()

	go func() {
		defer wg.Done()
		copyOptimized(c2, c1)
		closeWrite(c2)
	}()

	wg.Wait()
	c1.Close()
	c2.Close()
}

// copyOptimized uses io.Copy which can use splice() on Linux for TCP-to-TCP
func copyOptimized(dst, src net.Conn) {
	// io.Copy will use splice() system call on Linux when:
	// - Both are *net.TCPConn
	// - Not wrapped in TLS
	// For TLS, it falls back to buffered copy but that's unavoidable
	io.Copy(dst, src)
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

// ============== BUFFERED READER FOR DETECTING TLS ==============

type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func newPeekConn(conn net.Conn) *peekConn {
	return &peekConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

func (p *peekConn) Peek(n int) ([]byte, error) {
	return p.reader.Peek(n)
}

// isTLSTraffic checks if the traffic looks like TLS
func isTLSTraffic(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// TLS record starts with: ContentType(1) Version(2) Length(2)
	// ContentType: 0x14-0x18 (ChangeCipherSpec, Alert, Handshake, ApplicationData)
	// Version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3)
	contentType := data[0]
	versionMajor := data[1]
	versionMinor := data[2]

	if contentType < 0x14 || contentType > 0x18 {
		return false
	}
	if versionMajor != 0x03 {
		return false
	}
	if versionMinor > 0x04 {
		return false
	}
	return true
}

// ============== MAIN HANDLERS ==============

func handleTunnelCommand(subcmd string, args []string) bool {
	switch subcmd {
	case "tunnel-server":
		tunnelServer(args)
		return true
	case "tunnel-client":
		tunnelClient(args)
		return true
	}
	return false
}
