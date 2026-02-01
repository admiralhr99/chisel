package main

import (
	"crypto/tls"
	"encoding/base64"
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

	"github.com/jpillora/chisel/share/reality"
	utls "github.com/refraction-networking/utls"
)

// Fast TCP relay with Reality authentication - NO SSH overhead

var relayHelp = `
  Usage: chisel relay-server [options]
         chisel relay-client [options] <server> <local>:<remote>

  FAST TCP relay with Reality authentication (no SSH overhead).
  Use this for maximum speed when tunneling TCP traffic.

  relay-server options:
    --port, -p         Port to listen on (default: 8443)
    --tls-cert         TLS certificate file (required for TLS)
    --tls-key          TLS key file (required for TLS)
    --reality-privkey  Reality private key (from 'chisel genkey')
    --reality-shortid  Reality short ID
    -v                 Verbose logging

  relay-client options:
    --reality-pubkey   Reality public key
    --reality-shortid  Reality short ID
    --tls-skip-verify  Skip TLS certificate verification
    -v                 Verbose logging

  Examples:
    # Server (Germany)
    chisel relay-server -p 8443 --tls-cert cert.pem --tls-key key.pem \
      --reality-privkey "..." --reality-shortid "abc123"

    # Client (Iran) - forward local:30949 to server's localhost:30949
    chisel relay-client --reality-pubkey "..." --reality-shortid "abc123" \
      server.com:8443 0.0.0.0:30949:localhost:30949

    # Test speed with iperf3
    # Server: iperf3 -s -p 5201
    # Client tunnel: chisel relay-client ... server:8443 5201:localhost:5201
    # Test: iperf3 -c localhost -p 5201

`

const (
	bufferSize    = 64 * 1024 // 64KB buffer for speed
	authTimeout   = 10 * time.Second
	dialTimeout   = 10 * time.Second
	maxTargetLen  = 256
)

// relayServer runs the fast relay server
func relayServer(args []string) {
	flags := flag.NewFlagSet("relay-server", flag.ContinueOnError)

	port := flags.String("port", "8443", "")
	p := flags.String("p", "", "")
	tlsCert := flags.String("tls-cert", "", "")
	tlsKey := flags.String("tls-key", "", "")
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

	if *tlsCert != "" && *tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("Failed to load TLS cert: %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		listener, err = tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (TLS)", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Printf("relay-server: Listening on %s (no TLS)", addr)
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
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(authTimeout))

	// Read auth header (if Reality enabled)
	// Protocol: [1 byte: auth len][auth data][1 byte: target len][target string]
	if realityEnabled {
		// Read auth length
		authLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, authLenBuf); err != nil {
			if verbose {
				log.Printf("[%d] Failed to read auth length: %v", id, err)
			}
			return
		}
		authLen := binary.BigEndian.Uint16(authLenBuf)
		if authLen < 64 || authLen > 128 {
			if verbose {
				log.Printf("[%d] Invalid auth length: %d", id, authLen)
			}
			return
		}

		// Read auth data (sessionID + clientPubKey)
		authData := make([]byte, authLen)
		if _, err := io.ReadFull(conn, authData); err != nil {
			if verbose {
				log.Printf("[%d] Failed to read auth: %v", id, err)
			}
			return
		}

		// Parse session ID (32 bytes) and client public key (32 bytes)
		if len(authData) < 64 {
			if verbose {
				log.Printf("[%d] Auth data too short", id)
			}
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
			return
		}

		if verbose {
			log.Printf("[%d] Reality auth OK", id)
		}
	}

	// Read target length
	targetLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, targetLenBuf); err != nil {
		if verbose {
			log.Printf("[%d] Failed to read target length: %v", id, err)
		}
		return
	}
	targetLen := int(targetLenBuf[0])
	if targetLen == 0 || targetLen > maxTargetLen {
		if verbose {
			log.Printf("[%d] Invalid target length: %d", id, targetLen)
		}
		return
	}

	// Read target address
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(conn, targetBuf); err != nil {
		if verbose {
			log.Printf("[%d] Failed to read target: %v", id, err)
		}
		return
	}
	target := string(targetBuf)

	// Clear deadline
	conn.SetDeadline(time.Time{})

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
		log.Printf("[%d] Connected: client -> %s", id, target)
	}

	// Relay data
	sent, recv := relay(conn, targetConn)

	if verbose {
		log.Printf("[%d] Closed: sent=%d recv=%d", id, sent, recv)
	}
}

// relayClient runs the fast relay client
func relayClient(args []string) {
	flags := flag.NewFlagSet("relay-client", flag.ContinueOnError)

	realityPubkey := flags.String("reality-pubkey", "", "")
	realityShortID := flags.String("reality-shortid", "", "")
	tlsSkipVerify := flags.Bool("tls-skip-verify", false, "")
	verbose := flags.Bool("v", false, "")

	flags.Usage = func() {
		fmt.Print(relayHelp)
		os.Exit(0)
	}
	flags.Parse(args)

	args = flags.Args()
	if len(args) < 2 {
		log.Fatal("Usage: chisel relay-client [options] <server> <local>:<remote>")
	}

	server := args[0]
	mapping := args[1]

	// Parse mapping: local:remote or local:remotehost:remoteport
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
	useTLS := strings.HasSuffix(server, ":443") ||
		strings.HasSuffix(server, ":8443") ||
		strings.Contains(server, "https")

	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimPrefix(server, "http://")
	if !strings.Contains(server, ":") {
		if useTLS {
			server += ":443"
		} else {
			server += ":8080"
		}
	}

	log.Printf("relay-client: Forwarding %s -> %s -> %s", localAddr, server, remoteAddr)
	if realityEnabled {
		log.Printf("relay-client: Reality authentication enabled")
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
		go handleLocalConnection(localConn, id, server, remoteAddr, pubKey, shortID, realityEnabled, useTLS, *tlsSkipVerify, *verbose)
	}
}

func handleLocalConnection(localConn net.Conn, id int64, server, remoteAddr string, pubKey [32]byte, shortID []byte, realityEnabled, useTLS, tlsSkipVerify, verbose bool) {
	defer localConn.Close()

	// Connect to server
	var serverConn net.Conn
	var err error

	if useTLS {
		if realityEnabled {
			// Use uTLS for Chrome fingerprint
			tcpConn, err := net.DialTimeout("tcp", server, dialTimeout)
			if err != nil {
				if verbose {
					log.Printf("[%d] Failed to connect to server: %v", id, err)
				}
				return
			}

			host, _, _ := net.SplitHostPort(server)
			utlsConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: tlsSkipVerify,
			}

			tlsConn := utls.UClient(tcpConn, utlsConfig, utls.HelloChrome_Auto)
			if err := tlsConn.Handshake(); err != nil {
				tcpConn.Close()
				if verbose {
					log.Printf("[%d] TLS handshake failed: %v", id, err)
				}
				return
			}
			serverConn = tlsConn
		} else {
			// Standard TLS
			serverConn, err = tls.DialWithDialer(
				&net.Dialer{Timeout: dialTimeout},
				"tcp",
				server,
				&tls.Config{InsecureSkipVerify: tlsSkipVerify},
			)
			if err != nil {
				if verbose {
					log.Printf("[%d] Failed to connect to server: %v", id, err)
				}
				return
			}
		}
	} else {
		serverConn, err = net.DialTimeout("tcp", server, dialTimeout)
		if err != nil {
			if verbose {
				log.Printf("[%d] Failed to connect to server: %v", id, err)
			}
			return
		}
	}
	defer serverConn.Close()

	// Send auth and target
	serverConn.SetDeadline(time.Now().Add(authTimeout))

	if realityEnabled {
		// Create Reality session
		sessionID, clientPubKey, err := reality.CreateSessionID(pubKey, shortID)
		if err != nil {
			if verbose {
				log.Printf("[%d] Failed to create session: %v", id, err)
			}
			return
		}

		// Send auth: [2 bytes: len][32 bytes sessionID][32 bytes pubkey]
		authData := make([]byte, 64)
		copy(authData[:32], sessionID[:])
		copy(authData[32:], clientPubKey[:])

		authLen := make([]byte, 2)
		binary.BigEndian.PutUint16(authLen, uint16(len(authData)))

		if _, err := serverConn.Write(authLen); err != nil {
			if verbose {
				log.Printf("[%d] Failed to send auth length: %v", id, err)
			}
			return
		}
		if _, err := serverConn.Write(authData); err != nil {
			if verbose {
				log.Printf("[%d] Failed to send auth: %v", id, err)
			}
			return
		}
	}

	// Send target: [1 byte: len][target string]
	targetBytes := []byte(remoteAddr)
	if len(targetBytes) > maxTargetLen {
		if verbose {
			log.Printf("[%d] Target too long", id)
		}
		return
	}

	if _, err := serverConn.Write([]byte{byte(len(targetBytes))}); err != nil {
		if verbose {
			log.Printf("[%d] Failed to send target length: %v", id, err)
		}
		return
	}
	if _, err := serverConn.Write(targetBytes); err != nil {
		if verbose {
			log.Printf("[%d] Failed to send target: %v", id, err)
		}
		return
	}

	// Clear deadline
	serverConn.SetDeadline(time.Time{})

	if verbose {
		log.Printf("[%d] Connected: local -> %s -> %s", id, server, remoteAddr)
	}

	// Relay
	sent, recv := relay(localConn, serverConn)

	if verbose {
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
