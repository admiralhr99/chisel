# Implementation Ideas for Faster Tunneling

Based on research of Backhaul, Xray, Hysteria2, and other high-performance tunnels.

---

## Current Chisel Relay Performance Issues

### Identified Bottlenecks

1. **No connection pooling** - New TLS handshake for forward mode connections
2. **Conservative buffer sizes** - 512KB receive buffer may be too small
3. **Single SMUX connection** - Head-of-line blocking under load
4. **No socket buffer tuning** - Missing SO_RCVBUF/SO_SNDBUF optimization
5. **Aggressive keepalive** - 5s interval may cause overhead

---

## Improvements from Backhaul Analysis

### 1. Connection Pool (High Impact)

Backhaul pre-establishes connections to avoid TLS handshake latency.

```go
// Connection pool implementation
type ConnectionPool struct {
    mu       sync.Mutex
    conns    chan net.Conn
    factory  func() (net.Conn, error)
    size     int
}

func NewConnectionPool(size int, factory func() (net.Conn, error)) *ConnectionPool {
    pool := &ConnectionPool{
        conns:   make(chan net.Conn, size),
        factory: factory,
        size:    size,
    }
    // Pre-warm pool
    for i := 0; i < size; i++ {
        if conn, err := factory(); err == nil {
            pool.conns <- conn
        }
    }
    return pool
}

func (p *ConnectionPool) Get() (net.Conn, error) {
    select {
    case conn := <-p.conns:
        return conn, nil
    default:
        return p.factory()
    }
}

func (p *ConnectionPool) Put(conn net.Conn) {
    select {
    case p.conns <- conn:
    default:
        conn.Close() // Pool full
    }
}
```

**Configuration:**
```
--pool-size 8      # Number of pre-established connections
--aggressive-pool  # Dynamic pool sizing based on load
```

### 2. Larger SMUX Buffers for Throughput

Backhaul uses larger buffers for better throughput:

```go
func getSmuxConfigHighThroughput() *smux.Config {
    cfg := smux.DefaultConfig()
    cfg.Version = 2
    cfg.KeepAliveInterval = 20 * time.Second   // Less aggressive
    cfg.KeepAliveTimeout = 40 * time.Second
    cfg.MaxFrameSize = 32 * 1024               // 32KB (was 16KB)
    cfg.MaxReceiveBuffer = 4 * 1024 * 1024     // 4MB (was 512KB)
    cfg.MaxStreamBuffer = 256 * 1024           // 256KB
    return cfg
}

// Low latency config for web browsing
func getSmuxConfigLowLatency() *smux.Config {
    cfg := smux.DefaultConfig()
    cfg.Version = 2
    cfg.KeepAliveInterval = 10 * time.Second
    cfg.KeepAliveTimeout = 30 * time.Second
    cfg.MaxFrameSize = 16 * 1024               // Smaller frames
    cfg.MaxReceiveBuffer = 512 * 1024
    cfg.MaxStreamBuffer = 128 * 1024
    return cfg
}
```

**Configuration:**
```
--mode latency     # Low latency for web browsing
--mode throughput  # High throughput for downloads
```

### 3. Socket Buffer Tuning

Backhaul allows tuning OS socket buffers:

```go
func setSocketBuffers(conn net.Conn, recv, send int) {
    if tcpConn, ok := conn.(*net.TCPConn); ok {
        if recv > 0 {
            tcpConn.SetReadBuffer(recv)
        }
        if send > 0 {
            tcpConn.SetWriteBuffer(send)
        }
    }
}

// For localhost: smaller buffers (32KB)
// For remote: larger buffers (256KB-4MB depending on latency)
func optimalBufferSize(isLocalhost bool, latencyMs int) (recv, send int) {
    if isLocalhost {
        return 32 * 1024, 32 * 1024
    }
    // BDP = Bandwidth * Delay
    // For 100Mbps and 100ms latency: 100Mbps * 0.1s = 10Mb = 1.25MB
    switch {
    case latencyMs < 50:
        return 256 * 1024, 256 * 1024
    case latencyMs < 100:
        return 512 * 1024, 512 * 1024
    default:
        return 1024 * 1024, 1024 * 1024
    }
}
```

### 4. Multiple SMUX Sessions

Avoid head-of-line blocking with multiple sessions:

```go
type MultiSession struct {
    sessions []*smux.Session
    current  uint32
}

func (m *MultiSession) OpenStream() (*smux.Stream, error) {
    // Round-robin across sessions
    idx := atomic.AddUint32(&m.current, 1) % uint32(len(m.sessions))
    return m.sessions[idx].OpenStream()
}
```

**Configuration:**
```
--mux-sessions 4   # Number of parallel SMUX sessions
```

### 5. Adaptive Keepalive

Adjust based on network conditions:

```go
type AdaptiveKeepalive struct {
    minInterval time.Duration
    maxInterval time.Duration
    current     time.Duration
    lastPing    time.Time
}

func (a *AdaptiveKeepalive) OnSuccess() {
    // Increase interval on success (save bandwidth)
    a.current = min(a.current*2, a.maxInterval)
}

func (a *AdaptiveKeepalive) OnTimeout() {
    // Decrease interval on problems (faster recovery)
    a.current = max(a.current/2, a.minInterval)
}
```

---

## Advanced Features from Xray

### 1. Kernel Splice (Zero-Copy)

Xray uses Linux `splice()` for direct kernel-to-kernel copying:

```go
// splice() only works for raw TCP sockets (not TLS)
// For maximum speed, terminate TLS and use raw TCP internally

// This requires splitting the relay:
// [Client] --TLS--> [Server TLS termination] --raw TCP--> [Target]

// Go's io.Copy automatically uses splice when possible:
// - Both connections are *net.TCPConn
// - No application-level buffering

func relayWithSplice(dst, src *net.TCPConn) (int64, error) {
    // This will use splice() on Linux automatically
    return io.Copy(dst, src)
}
```

**Key insight:** SMUX prevents splice because it adds framing. For maximum speed:
- Use SMUX only for control/multiplexing
- Forward actual data through direct TCP connections

### 2. Direct TCP Mode (No Mux for Data)

```go
type HybridTunnel struct {
    controlSession *smux.Session  // For signaling
    directConns    map[string]net.Conn  // For data
}

// Signal through SMUX, transfer data directly
func (h *HybridTunnel) Forward(target string) {
    // 1. Request new direct connection via control
    // 2. Server opens direct TCP port
    // 3. Client connects directly for data
}
```

### 3. VLESS-like Minimal Protocol

VLESS has only 17 bytes overhead:

```go
// VLESS request format (17 bytes + address)
type VLESSRequest struct {
    Version  byte      // 1 byte: 0x00
    UUID     [16]byte  // 16 bytes: authentication
    AddrType byte      // 1 byte: address type
    // ... address and port follow
}

// Minimal relay protocol for chisel
type MinimalRequest struct {
    AuthHash [16]byte  // 16 bytes: HMAC of session
    AddrLen  byte      // 1 byte
    // Address follows (1-255 bytes)
}
```

---

## New Protocol Ideas

### 1. UDP-based Tunnel (like Hysteria2)

For networks where UDP works better:

```go
// QUIC-based tunnel
import "github.com/quic-go/quic-go"

func startQUICServer(addr string) {
    listener, _ := quic.ListenAddr(addr, tlsConfig, &quic.Config{
        EnableDatagrams: true,  // For UDP forwarding
        MaxIdleTimeout:  30 * time.Second,
    })

    for {
        conn, _ := listener.Accept(context.Background())
        go handleQUICConnection(conn)
    }
}
```

### 2. HTTP/3 Camouflage

Make tunnel look like HTTP/3 traffic:

```go
// Embed tunnel data in HTTP/3 frames
type HTTP3Tunnel struct {
    quicConn quic.Connection
}

func (t *HTTP3Tunnel) Send(data []byte) {
    // Wrap in HTTP/3 DATA frame
    frame := &http3DataFrame{
        Length: len(data),
        Data:   data,
    }
    t.quicConn.SendMessage(frame.Encode())
}
```

### 3. DNS Tunnel Integration

Fallback when everything else is blocked:

```go
// DNS tunnel uses TXT records for data
type DNSTunnel struct {
    domain string  // e.g., "tunnel.example.com"
    client *dns.Client
}

func (t *DNSTunnel) Send(data []byte) {
    encoded := base32.StdEncoding.EncodeToString(data)
    // Send as DNS query: <encoded>.tunnel.example.com
    t.client.Query(encoded + "." + t.domain, dns.TypeTXT)
}
```

### 4. WebTransport Tunnel

Modern HTTP/3 streaming:

```go
// WebTransport over HTTP/3
import "golang.org/x/net/http3"

func startWebTransportServer() {
    server := &http3.Server{
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Upgrade to WebTransport
            wt, _ := w.(http3.WebTransporter)
            session, _ := wt.AcceptSession()

            // Handle bidirectional streams
            for {
                stream, _ := session.AcceptStream()
                go handleStream(stream)
            }
        }),
    }
}
```

---

## Performance Configuration Recommendations

### For Web Browsing (Low Latency)

```bash
chisel relay-client \
    --mode latency \
    --pool-size 4 \
    --mux-sessions 2 \
    --frame-size 16384 \
    --keepalive 10s \
    server:443 R:30949:localhost:30949
```

### For Streaming/Downloads (High Throughput)

```bash
chisel relay-client \
    --mode throughput \
    --pool-size 8 \
    --mux-sessions 4 \
    --frame-size 32768 \
    --recv-buffer 4194304 \
    --keepalive 30s \
    server:443 R:30949:localhost:30949
```

### For Mixed Traffic (Balanced)

```bash
chisel relay-client \
    --mode balanced \
    --pool-size 6 \
    --mux-sessions 3 \
    --adaptive-buffers \
    server:443 R:30949:localhost:30949
```

---

## Implementation Priority

| Feature | Impact | Difficulty | Priority |
|---------|--------|------------|----------|
| Connection Pool | High | Medium | 1 |
| Multiple SMUX Sessions | High | Low | 2 |
| Socket Buffer Tuning | Medium | Low | 3 |
| Larger Frame Size | Medium | Low | 4 |
| Direct TCP Mode | Very High | High | 5 |
| QUIC Transport | High | High | 6 |

---

## Code Locations to Modify

| Feature | File | Function |
|---------|------|----------|
| SMUX Config | `relay.go` | `getSmuxConfig()` |
| Connection Handling | `relay.go` | `handleRelayConnection()` |
| Socket Options | `relay.go` | `dialServer()` |
| Keepalive | `relay.go` | `getSmuxConfig()` |
| Buffer Size | `relay.go` | `const bufferSize` |

---

## References

- [Backhaul GitHub](https://github.com/Musixal/Backhaul)
- [Xray Core](https://github.com/XTLS/Xray-core)
- [SMUX Documentation](https://github.com/xtaci/smux)
- [Linux splice()](https://man7.org/linux/man-pages/man2/splice.2.html)
- [QUIC RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
