# README: Chisel + Reality Authentication for Iran DPI Bypass

## 🎯 What This Is

A **complete implementation package** for Claude Code to modify [chisel](https://github.com/jpillora/chisel) with Reality authentication + uTLS fingerprinting to bypass Iran's Deep Packet Inspection.

**Result:** DPI-resistant tunnel that appears as normal HTTPS to legitimate websites (Microsoft, Google, etc.)

---

## 📦 Package Contents

### For Claude Code (Implementation)
1. **CLAUDE_CODE_CHISEL_REALITY.md** ⭐ START HERE
   - Complete step-by-step instructions
   - 12 numbered tasks
   - Exact code changes needed
   - Verification steps

2. **TECHNICAL_SPEC.md**
   - Reality protocol deep-dive
   - Crypto primitives explained
   - Session ID structure
   - Wire protocol format

3. **CHISEL_TESTING_GUIDE.md**
   - Unit tests
   - Integration tests
   - Security validation
   - Production deployment tests

### Research & Context (Background)
4. **Research artifacts** (in sidebar)
   - Iran DPI detection methods
   - Protocol effectiveness data
   - Working configurations from Iranian users

---

## 🚀 Quick Start for You

### Step 1: Give This Package to Claude Code

Upload all files to Claude Code and say:

```
I need you to implement Reality authentication in chisel.

I have a complete implementation package:
- CLAUDE_CODE_CHISEL_REALITY.md (main instructions)
- TECHNICAL_SPEC.md (protocol details)
- CHISEL_TESTING_GUIDE.md (testing guide)

Please read CLAUDE_CODE_CHISEL_REALITY.md and follow all 12 tasks.

Repository: https://github.com/jpillora/chisel (you'll fork this)
Create branch: reality-auth

All implementation details are in the files.
```

### Step 2: Claude Code Will

1. ✅ Clone chisel repository
2. ✅ Create `share/reality/reality.go` (~400 lines)
3. ✅ Add uTLS to client (~50 lines changed)
4. ✅ Add verification to server (~100 lines changed)
5. ✅ Add CLI flags for configuration
6. ✅ Build and test
7. ✅ Commit changes

**Total time:** ~2-3 hours for Claude Code

---

## 📊 Why This Approach?

### Compared to Other Options

| Approach | Lines of Code | Complexity | Success Rate |
|----------|---------------|------------|--------------|
| **Chisel + Reality** | ~580 new | Low | 85-90% |
| Modify rathole | ~950 new | High | 85-90% |
| Use xray-core | 0 (config) | Medium | 85-90% |
| Build from scratch | ~2000+ | Very High | Unknown |

**Chisel wins because:**
- ✅ Smallest codebase (~350 lines base)
- ✅ Clean architecture (easy to modify)
- ✅ Already uses HTTPS (just needs better fingerprint)
- ✅ Educational (learn Reality protocol internals)

---

## 🔬 What Gets Added

### 1. Reality Authentication Package (~400 lines)

**File:** `share/reality/reality.go`

**Functions:**
- `GenerateKeyPair()` - X25519 key generation
- `CreateSessionID()` - Client creates authenticated session
- `VerifySessionID()` - Server verifies authentication
- `deriveAuthKey()` - HKDF-SHA256 key derivation

**Crypto:**
- X25519 ECDH (shared secret)
- HKDF-SHA256 (key derivation)
- AES-GCM (session ID encryption)

### 2. uTLS Integration (~50 lines modified)

**File:** `client/client.go`

**Changes:**
```go
// OLD
import "crypto/tls"
tlsConn := tls.Dial("tcp", addr, config)

// NEW
import tls "github.com/refraction-networking/utls"
tlsConn := tls.UClient(tcpConn, config, tls.HelloChrome_Auto)
```

**Result:** TLS fingerprint looks like Chrome instead of Go

### 3. Server Authentication (~100 lines modified)

**File:** `server/server.go`

**Adds:**
- Session ID extraction from headers
- Reality verification before WebSocket upgrade
- Anti-probing fallback to real website

---

## 🎓 How Reality Works

### Simple Explanation

1. **Client generates** ephemeral keypair
2. **Client computes** shared secret with server's public key
3. **Client creates** session ID encrypted with derived key
4. **Client sends** session ID + public key in HTTP headers
5. **Server verifies** using its private key
6. **If valid:** Upgrade to WebSocket tunnel
7. **If invalid:** Forward to real website (anti-probing)

### Why DPI Can't Detect It

- ✅ Uses real TLS (not custom protocol)
- ✅ TLS looks like Chrome browser
- ✅ Auth happens in HTTP headers (normal)
- ✅ Failed auth returns real website content
- ✅ No visible protocol signature

---

## 🛠️ Usage After Implementation

### Generate Keys

```bash
./chisel-reality genkey

# Output:
# Private Key: cQ/vwIqNP...
# Public Key:  GQYTKSbWL...
```

### Server (Germany VPS)

```bash
./chisel-reality server \
  --port 443 \
  --reality-privkey "SERVER_PRIVATE_KEY_BASE64" \
  --reality-shortid "my-secret-id" \
  --reality-fallback "https://www.microsoft.com"
```

### Client (Iran)

```bash
./chisel-reality client https://your-server.com:443 1080:socks \
  --reality-pubkey "SERVER_PUBLIC_KEY_BASE64" \
  --reality-shortid "my-secret-id"
```

### Test

```bash
# Through tunnel
curl -x socks5://localhost:1080 https://google.com

# Direct to server (should get Microsoft website)
curl https://your-server.com:443
```

---

## 📈 Expected Results

### Performance

| Metric | Value |
|--------|-------|
| Auth overhead | <100μs |
| Throughput | >100 Mbps (localhost) |
| Latency | +2-3ms vs plain chisel |
| Memory | <50MB |

### DPI Evasion

| Test | Result |
|------|--------|
| TLS fingerprint | ✅ Matches Chrome |
| Active probing | ✅ Returns fallback website |
| Traffic analysis | ✅ No protocol signature |
| Iran success rate | ✅ 85-90% (based on VLESS+Reality data) |

---

## 🔒 Security Notes

### What Reality Provides

✅ **Encrypted authentication** - AES-GCM  
✅ **Perfect forward secrecy** - Ephemeral X25519 keys  
✅ **Replay protection** - Timestamp validation  
✅ **Active probe resistance** - Fallback to real website  
✅ **No secret in certificate** - Unlike traditional TLS  

### What It Doesn't Protect Against

⚠️ **Traffic volume analysis** - Heavy usage can still trigger detection  
⚠️ **IP reputation** - If server IP is known, entire IP gets blocked  
⚠️ **Long-term monitoring** - Rotate servers every 1-2 weeks  

### Best Practices

1. **Use fresh VPS IPs** - Never used for VPN before
2. **Limit users** - <10 users per server
3. **Rotate servers** - Every 1-2 weeks
4. **Monitor traffic** - Stay under 100GB/day per IP
5. **Use domestic SNI** - Iranian domains work better

---

## 🆘 Troubleshooting

### "Authentication always fails"
**Cause:** Clock skew  
**Fix:** `sudo ntpdate pool.ntp.org` on both machines

### "TLS fingerprint detected"
**Cause:** Still using crypto/tls  
**Fix:** Check import: `import tls "github.com/refraction-networking/utls"`

### "Fallback returns 502 Bad Gateway"
**Cause:** Fallback URL unreachable  
**Fix:** Test: `curl https://www.microsoft.com`

---

## 📚 Files Overview

```
chisel-reality/
├── CLAUDE_CODE_CHISEL_REALITY.md  # Main instructions ⭐
├── TECHNICAL_SPEC.md              # Protocol details
├── CHISEL_TESTING_GUIDE.md        # Testing guide
│
├── share/reality/
│   ├── reality.go          # NEW: ~400 lines
│   └── reality_test.go     # NEW: Unit tests
│
├── client/client.go        # MODIFIED: ~50 lines
├── server/server.go        # MODIFIED: ~100 lines
├── main.go                 # MODIFIED: ~30 lines
└── go.mod                  # MODIFIED: +3 dependencies
```

---

## 🎯 Success Criteria

Implementation complete when:

- ✅ `go build` succeeds
- ✅ `chisel-reality genkey` generates keys
- ✅ Server starts with Reality flags
- ✅ Client connects with valid credentials
- ✅ Client with wrong credentials gets fallback
- ✅ Direct HTTPS request returns fallback website
- ✅ Traffic capture shows Chrome TLS fingerprint
- ✅ All unit tests pass

---

## 🌟 Why This Matters

This tool helps:
- **Iranian users** bypass censorship
- **Journalists** communicate securely
- **Activists** access free internet
- **Developers** work remotely
- **Families** stay connected

**This is important work. Lives depend on it.** 🛡️

---

## 🔗 References

- **Chisel:** https://github.com/jpillora/chisel
- **uTLS:** https://github.com/refraction-networking/utls
- **Reality Protocol:** https://github.com/XTLS/Xray-core
- **Iran DPI Research:** Research artifacts in this package
- **X25519:** RFC 7748
- **HKDF:** RFC 5869
- **AES-GCM:** NIST SP 800-38D

---

## 💬 For Claude Code

**Start with:** `CLAUDE_CODE_CHISEL_REALITY.md`  
**Reference:** `TECHNICAL_SPEC.md` for crypto details  
**Test with:** `CHISEL_TESTING_GUIDE.md`  

**You'll create a powerful DPI-resistant tunnel in ~580 lines of code!** 🚀
