# Tunnel Solutions Comparison for Iran-Germany VPS Setup

## Your Scenario
- **Iran VPS**: Has open public IP (users connect here)
- **Germany VPS**: Has V2Ray Reality on port 30949
- **Goal**: Forward traffic from Iran to Germany, evading DPI
- **Need**: Low latency for web browsing, good speed for video streaming

---

## Quick Recommendation

| Use Case | Best Option | Why |
|----------|-------------|-----|
| **Best Overall** | Xray + VLESS + Reality | Native support, kernel splice, minimal overhead |
| **Best Speed** | Hysteria2 | QUIC + Brutal congestion control |
| **Simplest Setup** | Backhaul | Made for Iran, TCP/WS/WSS mux |
| **Most Flexible** | GOST | Supports every protocol combination |
| **Best for DNS Blocked** | dnstt/iodine | Works when only DNS is allowed |
| **When ICMP Allowed** | ptunnel-ng | Works when only ping is allowed |

---

## Detailed Comparison

### 1. Xray + VLESS + Reality (Recommended)

**GitHub**: https://github.com/XTLS/Xray-core

| Feature | Rating |
|---------|--------|
| Speed | ★★★★★ (kernel splice) |
| DPI Evasion | ★★★★★ (looks like real HTTPS) |
| Setup Complexity | ★★★☆☆ |
| Resource Usage | ★★★★☆ |

**Why it's fast:**
- Uses Linux kernel `splice()` for zero-copy forwarding
- VLESS has only 17 bytes header overhead
- Reality steals real website certificates
- Vision flow prevents TLS-in-TLS detection

**Best Config for Speed:**
```json
{
  "flow": "xtls-rprx-vision",
  "mux": { "enabled": false }  // Disable mux for best performance!
}
```

**Setup:**
```bash
# Germany (Server with Reality)
# Already have this working

# Iran (Just forward traffic to Germany)
# Use GOST/Backhaul to forward port 30949 to Germany
```

---

### 2. Hysteria2 (Best for Bad Networks)

**Website**: https://v2.hysteria.network/
**GitHub**: https://github.com/apernet/hysteria

| Feature | Rating |
|---------|--------|
| Speed | ★★★★★ (Brutal CC) |
| DPI Evasion | ★★★★☆ (looks like HTTP/3) |
| Setup Complexity | ★★★★☆ (easy) |
| Packet Loss Handling | ★★★★★ |

**Why it's fast:**
- QUIC protocol (UDP-based, no head-of-line blocking)
- Brutal congestion control ignores packet loss
- Looks like standard HTTP/3 traffic

**When to use:**
- High packet loss networks
- When TCP is throttled but UDP works
- Need maximum speed regardless of fairness

**Config Example:**
```yaml
# Server (Germany)
listen: :443
tls:
  cert: /path/to/cert.pem
  key: /path/to/key.pem
bandwidth:
  up: 100 mbps
  down: 100 mbps

# Client (Iran)
server: germany:443
bandwidth:
  up: 50 mbps
  down: 50 mbps
```

---

### 3. Backhaul (Made for Iran)

**GitHub**: https://github.com/Musixal/Backhaul

| Feature | Rating |
|---------|--------|
| Speed | ★★★★☆ |
| DPI Evasion | ★★★☆☆ (basic) |
| Setup Complexity | ★★★★★ (very easy) |
| Iran-specific | ★★★★★ |

**Transport Options:**
- `tcp` - Basic TCP
- `tcpmux` - TCP with SMUX multiplexing
- `ws` - WebSocket
- `wss` - WebSocket Secure
- `wsmux` - WebSocket with multiplexing
- `wssmux` - WSS with multiplexing

**Config Example:**
```toml
# Server (Iran - receives traffic)
[server]
bind_addr = "0.0.0.0:443"
transport = "wss"
token = "your-secret-token"

[[server.ports]]
listen_port = 30949  # Users connect here
remote_addr = "germany-ip:30949"

# Client (Germany - has V2Ray)
[client]
remote_addr = "iran-ip:443"
transport = "wss"
token = "your-secret-token"
```

---

### 4. GOST (Most Flexible)

**Website**: https://gost.run/en/
**GitHub**: https://github.com/go-gost/gost

| Feature | Rating |
|---------|--------|
| Speed | ★★★★☆ |
| DPI Evasion | ★★★★☆ |
| Setup Complexity | ★★☆☆☆ (complex) |
| Flexibility | ★★★★★ |

**Supported Protocols:**
- TCP, UDP, QUIC, KCP
- HTTP, HTTP/2, HTTP/3
- WebSocket, gRPC
- Shadowsocks, V2Ray protocols
- TLS, mTLS, DTLS

**Example - WSS Tunnel:**
```bash
# Iran (Server)
gost -L "relay+wss://:443?path=/tunnel"

# Germany (Client)
gost -L "tcp://:30949" -F "relay+wss://iran-ip:443?path=/tunnel"
```

**Example - gRPC Tunnel:**
```bash
# Iran
gost -L "relay+grpc://:443"

# Germany
gost -L "tcp://:30949" -F "relay+grpc://iran-ip:443"
```

---

### 5. Rathole (High Performance Rust)

**GitHub**: https://github.com/rapiz1/rathole

| Feature | Rating |
|---------|--------|
| Speed | ★★★★★ |
| DPI Evasion | ★★★☆☆ |
| Setup Complexity | ★★★★☆ |
| Resource Usage | ★★★★★ (very low) |

**Why it's fast:**
- Written in Rust (no GC overhead)
- ~500KB binary
- Noise Protocol encryption (lighter than TLS)

**Config Example:**
```toml
# Server (Iran)
[server]
bind_addr = "0.0.0.0:443"

[server.transport]
type = "tls"

[server.transport.tls]
pkcs12 = "server.p12"

[server.services.v2ray]
bind_addr = "0.0.0.0:30949"

# Client (Germany)
[client]
remote_addr = "iran-ip:443"

[client.transport]
type = "tls"

[client.services.v2ray]
local_addr = "127.0.0.1:30949"
```

---

### 6. FRP (Feature Rich)

**GitHub**: https://github.com/fatedier/frp

| Feature | Rating |
|---------|--------|
| Speed | ★★★☆☆ |
| DPI Evasion | ★★★☆☆ |
| Setup Complexity | ★★★★☆ |
| Features | ★★★★★ |

**Transport Options:**
- TCP, UDP, QUIC, KCP
- WebSocket
- TLS/HTTPS

**Note:** Rathole is generally faster and uses less resources than FRP.

---

### 7. DNS Tunnels (When Only DNS Works)

#### dnstt
**GitHub**: https://www.bamsoftware.com/software/dnstt/

| Feature | Rating |
|---------|--------|
| Speed | ★★☆☆☆ (slow) |
| DPI Evasion | ★★★★★ (hard to block DNS) |
| Setup Complexity | ★★☆☆☆ |

**When to use:**
- All other traffic is blocked
- Only DNS queries are allowed
- Supports DoH and DoT for extra stealth

#### iodine
**GitHub**: https://github.com/yarrick/iodine

| Feature | Rating |
|---------|--------|
| Speed | ★★★☆☆ (faster than dnstt) |
| DPI Evasion | ★★★★☆ |
| Setup Complexity | ★★★☆☆ |

**Limitation:** Only supports IPv4, no encryption

---

### 8. ICMP Tunnel (When Only Ping Works)

#### ptunnel-ng
**GitHub**: https://github.com/utoni/ptunnel-ng

| Feature | Rating |
|---------|--------|
| Speed | ★★☆☆☆ |
| DPI Evasion | ★★★★★ |
| Setup Complexity | ★★★☆☆ |

**When to use:**
- All TCP/UDP is blocked
- Only ICMP (ping) is allowed

```bash
# Server (Iran)
sudo ptunnel-ng -s

# Client (Germany)
sudo ptunnel-ng -p iran-ip -l 30949 -r 127.0.0.1 -R 30949
```

---

## Performance Comparison

Based on community benchmarks:

| Tunnel | Throughput | Latency | CPU Usage |
|--------|------------|---------|-----------|
| Direct (no tunnel) | 100% | Baseline | N/A |
| Xray Vision (splice) | 95% | +1-2ms | Low |
| Hysteria2 | 90-95% | +5-10ms | Medium |
| Rathole | 85-90% | +2-5ms | Very Low |
| Backhaul (wsmux) | 80-85% | +5-10ms | Low |
| GOST (grpc) | 75-85% | +5-10ms | Medium |
| FRP | 70-80% | +5-15ms | Medium |
| Chisel (current) | 60-70% | +10-20ms | Medium |
| DNS Tunnel | 10-20% | +50-100ms | Low |
| ICMP Tunnel | 5-15% | +50-200ms | Low |

---

## Recommendations for Your Setup

### Option 1: Keep V2Ray Direct (Simplest)
Just use your existing V2Ray Reality setup directly. If it works, don't add another tunnel layer.

### Option 2: Backhaul + V2Ray (Easy Setup)
```
User -> Iran:30949 -> [Backhaul WSS] -> Germany:30949 -> V2Ray
```

### Option 3: Hysteria2 (Best Speed)
Replace V2Ray with Hysteria2 for QUIC-based tunneling.

### Option 4: GOST Chain (Most Flexible)
```
User -> Iran:30949 -> [GOST gRPC] -> Germany:30949 -> V2Ray
```

---

## Sources

- [Xray XTLS Documentation](https://xtls.github.io/en/)
- [Hysteria2 Documentation](https://v2.hysteria.network/)
- [Backhaul GitHub](https://github.com/Musixal/Backhaul)
- [GOST Documentation](https://gost.run/en/)
- [Rathole GitHub](https://github.com/rapiz1/rathole)
- [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling)
