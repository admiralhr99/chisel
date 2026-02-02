# DPI Evasion Techniques Guide

## Overview

Deep Packet Inspection (DPI) is used by network operators to identify and block VPN/proxy traffic. This guide covers techniques to evade DPI, with focus on Iran's network restrictions.

---

## How DPI Works

### Traffic Analysis Methods

1. **Protocol Fingerprinting**
   - Analyzes packet headers and payload patterns
   - Identifies VPN protocols by known signatures
   - Detects TLS fingerprints (cipher suites, extensions)

2. **Timing Analysis**
   - Measures packet intervals and sizes
   - Detects proxy patterns vs normal browsing

3. **SNI Inspection**
   - Reads Server Name Indication in TLS handshake
   - Blocks connections to known VPN domains

4. **Statistical Analysis**
   - Analyzes traffic patterns (entropy, packet sizes)
   - ML-based detection of encrypted tunnels

---

## Evasion Techniques

### 1. TLS Fingerprint Mimicry

**Problem:** DPI can identify VPN clients by their unique TLS fingerprints.

**Solution:** Use uTLS to mimic real browser fingerprints.

```go
// Use Chrome fingerprint
import utls "github.com/refraction-networking/utls"

config := &utls.Config{
    ServerName: "www.google.com",  // SNI spoofing
    NextProtos: []string{"h2", "http/1.1"},  // ALPN
}
conn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
```

**Popular fingerprints:**
- `HelloChrome_Auto` - Chrome browser (best compatibility)
- `HelloFirefox_Auto` - Firefox browser
- `HelloSafari_Auto` - Safari browser
- `HelloRandomized` - Random fingerprint

### 2. SNI Spoofing

**Problem:** DPI blocks connections to VPN server IPs/domains.

**Solution:** Use SNI of popular, unblocked websites.

**Good SNI choices for Iran:**
- `www.google.com`
- `www.microsoft.com`
- `www.apple.com`
- `cdn.cloudflare.com`
- `www.amazon.com`
- `www.github.com`

**Bad choices (often blocked):**
- VPN/proxy related domains
- Adult content domains
- Known censored sites

### 3. ALPN Negotiation

**Problem:** Unusual ALPN values can flag traffic.

**Solution:** Use standard HTTP/2 ALPN like real browsers.

```go
tlsConfig := &tls.Config{
    NextProtos: []string{"h2", "http/1.1"},  // Standard browser ALPN
}
```

### 4. Port Selection

**Common ports that work:**
- `443` - HTTPS (best choice)
- `8443` - Alternative HTTPS
- `80` - HTTP (no encryption, not recommended)

**Ports to avoid:**
- Known VPN ports (1194, 1723, 500, 4500)
- SSH (22) - often rate limited
- Unusual high ports - may be flagged

### 5. Packet Padding

**Problem:** Encrypted packets with predictable sizes can be detected.

**Solution:** Add random padding to packets.

```go
// Add 0-255 random bytes of padding
padding := make([]byte, rand.Intn(256))
rand.Read(padding)
payload = append(payload, padding...)
```

### 6. Traffic Pattern Obfuscation

**Problem:** VPN traffic has distinctive patterns.

**Techniques:**
- Random delays between packets
- Variable packet sizes
- Mimicking web browsing patterns (request/response asymmetry)

---

## Protocol-Specific Techniques

### Reality Protocol (Xray)

The most advanced DPI evasion:

1. **No TLS fingerprint** - Uses real website's TLS
2. **Perfect forward secrecy** - Each session has unique keys
3. **Steals real certificates** - Acts as TLS proxy to real site
4. **Zero detectable overhead** - Traffic looks identical to HTTPS

```
Client -> [TLS to VPN server] -> [Server validates with Reality auth]
                              -> [Server proxies to real website if auth fails]
```

### VLESS Vision Flow

Prevents TLS-in-TLS detection:

1. **No inner TLS** - Uses raw encryption after outer TLS
2. **Padding frames** - Random data mixed in
3. **Kernel splice** - Zero-copy forwarding (no pattern)

### Hysteria2

QUIC-based evasion:

1. **Looks like HTTP/3** - Standard QUIC protocol
2. **Brutal CC** - Ignores throttling attempts
3. **Obfuscation** - Optional traffic obfuscation

---

## Iran-Specific Recommendations

### What Works

1. **Reality + VLESS** - Best success rate
2. **Hysteria2** - When UDP is not blocked
3. **WebSocket over TLS** - Good fallback
4. **gRPC** - Looks like legitimate API traffic

### What Usually Gets Blocked

1. **Pure OpenVPN** - Easily detected
2. **Shadowsocks (vanilla)** - Known patterns
3. **WireGuard** - UDP fingerprint detected
4. **Tor bridges** - Most are blocked

### Testing Your Setup

```bash
# Test if port is reachable
nc -zv your-server 443

# Test TLS fingerprint (from client)
curl -v --tlsv1.2 https://your-server:443/

# Test with actual browser (best test)
# Open browser, navigate to https://your-server:443/
# If you see website content, TLS is working
```

---

## Implementation Checklist

- [ ] Use TLS on port 443
- [ ] Enable uTLS with Chrome fingerprint
- [ ] Set SNI to popular, unblocked domain
- [ ] Use ALPN `h2, http/1.1`
- [ ] Generate valid-looking certificate
- [ ] Enable TCP_NODELAY for responsiveness
- [ ] Consider Reality protocol for maximum stealth

---

## Detection Risks by Method

| Method | Detection Risk | Speed Impact |
|--------|---------------|--------------|
| Reality | Very Low | Minimal |
| uTLS + SNI spoof | Low | Minimal |
| Plain TLS | Medium | None |
| WebSocket | Low | +5-10% |
| gRPC | Low | +5-10% |
| Shadowsocks | Medium-High | None |
| OpenVPN | Very High | None |

---

## Tools for Testing

1. **Wireshark** - Analyze your own traffic
2. **curl with verbose** - Check TLS handshake
3. **ssllabs.com** - Test TLS configuration
4. **ja3er.com** - Check TLS fingerprint

---

## References

- [uTLS GitHub](https://github.com/refraction-networking/utls)
- [Xray Reality Documentation](https://xtls.github.io/en/config/features/reality.html)
- [IETF TLS 1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- [GFW Report](https://gfw.report/) - Great Wall research
