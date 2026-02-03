# Claude Project: High-Performance Anti-DPI Tunnel Protocol

## Project Goal

Create a new tunnel protocol optimized for:
1. **Iran DPI evasion** - Bypass sophisticated Deep Packet Inspection
2. **High performance** - Match or exceed Xray/V2Ray/Backhaul speeds
3. **Stealth** - Traffic indistinguishable from normal HTTPS
4. **Simplicity** - Single binary, easy deployment

## Architecture Overview

```
User (Iran) → V2Ray Client → Iran VPS:30949 → [TUNNEL] → Germany VPS:30949 → V2Ray Server → Internet
```

The tunnel bridges two VPS servers, forwarding traffic through Iran's firewall.

## Technical Context

### Iran DPI Behavior
- Analyzes first 3-5 packets heavily
- Detects high-bandwidth connections
- Graylist approach: suspicious traffic gets throttled, then blocked
- Blocks popular VPN SNIs
- Detects TLS-in-TLS patterns
- Active probing of suspected servers

### Why Existing Tools Are Fast

#### XTLS Vision (Xray)
```go
// Detects inner TLS traffic and uses raw splice
if isInnerTLS(data) {
    // Switch to splice() - zero-copy, kernel-level
    syscall.Splice(src, dst)
} else {
    // Normal encrypted relay
    tlsConn.Write(encrypt(data))
}
```
Key insight: When TLS wraps TLS, outer encryption is redundant. XTLS skips it.

#### VLESS Protocol
```
+--------+----------+------+
| 1 byte | 16 bytes | data |
| version|   UUID   |      |
+--------+----------+------+
```
Only 17 bytes overhead vs VMess's 32+ bytes.

#### splice() System Call
```go
// Zero-copy: kernel moves data directly between sockets
syscall.Splice(srcFd, nil, dstFd, nil, bufferSize, SPLICE_F_MOVE)
```
Problem: Cannot use with TLS (encryption happens in userspace).

### Current Implementation Files

- `tunnel.go` - Main tunnel implementation (~900 lines)
- `main.go` - CLI entry points
- `relay.go` - Earlier SMUX-based relay (superseded)

### Key Components in tunnel.go

```go
// Connection pooling for instant connections
type ConnPool struct {
    conns   chan net.Conn
    factory func() (net.Conn, error)
    size    int
}

// TLS fragmentation for DPI evasion
type FragmentedConn struct {
    net.Conn
    minSize, maxSize   int
    minDelay, maxDelay int
}

// Direct relay without SMUX overhead
func relay(client, remote net.Conn) {
    go io.Copy(remote, client)
    io.Copy(client, remote)
}
```

## Research References

### Must-Read Codebases

1. **Xray-core** - https://github.com/XTLS/Xray-core
   - `proxy/vless/` - VLESS protocol
   - `transport/internet/xtls/` - XTLS Vision
   - Key file: `common/buf/copy.go`

2. **sing-box** - https://github.com/SagerNet/sing-box
   - Clean Go implementation
   - `transport/` - Transport layers
   - `option/` - Configuration

3. **Backhaul** - https://github.com/Musixal/Backhaul
   - High performance Iran-specific
   - Key file: `internal/client/transport/`

4. **Reality** - https://github.com/XTLS/REALITY
   - Server impersonation
   - TLS 1.3 with stolen certificates

### Key Papers/Docs

1. **GFW Report** - https://gfw.report/
   - Iran censorship analysis
   - DPI detection methods

2. **TLS Fingerprinting** - https://tlsfingerprint.io/
   - How DPI identifies TLS clients
   - JA3/JA4 fingerprints

3. **uTLS Library** - https://github.com/refraction-networking/utls
   - Browser TLS fingerprint mimicry
   - Chrome/Firefox/Safari presets

## Performance Bottlenecks

### Problem 1: TLS-in-TLS
```
User Data → TLS (V2Ray) → TLS (Tunnel) → Wire
```
Double encryption = 2x CPU usage.

**Solution**: XTLS Vision approach - detect inner TLS, skip outer encryption.

### Problem 2: SMUX Overhead
```
+--------+---------+------+-------+
| version| cmd     | len  | data  |
| 1 byte | 1 byte  | 2B   | ...   |
+--------+---------+------+-------+
```
Every packet gets 4+ bytes overhead, plus flow control delays.

**Solution**: Direct relay without multiplexing. One tunnel connection per user connection.

### Problem 3: Buffer Copies
```go
// Bad: multiple copies
buf := make([]byte, 32*1024)
n, _ := src.Read(buf)
dst.Write(buf[:n])  // Copy to kernel
```

**Solution**: splice() for non-TLS, larger buffers for TLS.

### Problem 4: Iran DPI First-Packet Analysis
First 3-5 packets heavily analyzed.

**Solutions**:
- TLS fragmentation (split handshake)
- Random padding
- SNI spoofing
- Connection timing randomization

## Ideal Protocol Design

### Header Format (Minimal)
```
+------+--------+------+
| 1B   | 2B     | data |
| cmd  | length |      |
+------+--------+------+
```
Only 3 bytes overhead.

### Commands
```
0x01 - New connection (include dest addr)
0x02 - Data
0x03 - Close
0x04 - Keepalive
```

### Connection Flow
```
1. Client connects with TLS (uTLS fingerprint)
2. Client sends auth (HMAC-SHA256)
3. Server validates
4. Client sends tunnel request
5. Bidirectional relay begins
```

### DPI Evasion Layers
```
Layer 1: TLS 1.3 with browser fingerprint
Layer 2: SNI of popular domain (microsoft.com)
Layer 3: Fragmented ClientHello
Layer 4: Random padding to mask traffic patterns
Layer 5: Traffic shaping (avoid burst patterns)
```

## Implementation Roadmap

### Phase 1: Working Tunnel (Current)
- [x] Basic TLS tunnel
- [x] Connection pooling
- [x] SNI spoofing
- [x] Fragmentation (optional)
- [ ] Stable connection under Iran DPI

### Phase 2: Performance
- [ ] Implement XTLS Vision detection
- [ ] Add splice() for raw TCP
- [ ] Remove all unnecessary buffering
- [ ] Optimize for throughput

### Phase 3: Stealth
- [ ] uTLS fingerprint rotation
- [ ] Traffic pattern analysis evasion
- [ ] Active probing resistance
- [ ] Reality-style server impersonation

### Phase 4: Advanced
- [ ] Multi-path connections
- [ ] Happy Eyeballs (IPv4/IPv6)
- [ ] QUIC/UDP support
- [ ] Bandwidth aggregation

## Testing Commands

### Build
```bash
go build -o chisel .
```

### Server (Iran VPS - has open IP)
```bash
./chisel tunnel-server -p 443 --password "YOUR_PASSWORD" -v
```

### Client (Germany VPS - has V2Ray)
```bash
./chisel tunnel-client \
    --password "YOUR_PASSWORD" \
    --pool-size 4 \
    --sni "www.microsoft.com" \
    -v \
    IRAN_IP:443 \
    R:30949:localhost:30949
```

### Test Connection
```bash
# From Iran VPS
curl -v http://localhost:30949
```

## Code Style Guidelines

1. **No unnecessary abstractions** - Direct code over interfaces
2. **Inline hot paths** - Avoid function calls in relay loops
3. **Preallocate buffers** - Reuse byte slices
4. **Minimize allocations** - Use sync.Pool
5. **Profile before optimizing** - Use pprof

## Useful Go Patterns

### Zero-copy with splice
```go
import "golang.org/x/sys/unix"

func splice(src, dst *os.File, size int) (int64, error) {
    return unix.Splice(int(src.Fd()), nil, int(dst.Fd()), nil, size, unix.SPLICE_F_MOVE)
}
```

### Buffer pooling
```go
var bufPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 64*1024)
    },
}

buf := bufPool.Get().([]byte)
defer bufPool.Put(buf)
```

### Efficient relay
```go
func relay(dst, src net.Conn, buf []byte) (int64, error) {
    return io.CopyBuffer(dst, src, buf)
}
```

## Debugging Tips

### Verbose connection logging
```bash
./chisel tunnel-client -v ...
```

### Packet capture
```bash
tcpdump -i eth0 port 443 -w capture.pcap
```

### TLS analysis
```bash
ssldump -i eth0 port 443
```

### Check if connection blocked
```bash
curl -v --connect-timeout 5 https://IRAN_IP:443
```

## Known Issues

1. **TLS handshake EOF** - Usually wrong TLS settings or aggressive fragmentation
2. **Auth timeout** - Iran DPI may be blocking; try different SNI
3. **Slow after initial burst** - DPI throttling; implement traffic shaping
4. **Connection reset** - Server might be actively probed; implement Reality

## Contact & Resources

- Xray Telegram: @projectXray
- Iran Censorship Research: gfw.report
- TLS Fingerprinting: tlsfingerprint.io

---

*This document is for Claude AI to understand the project context and assist with development.*
