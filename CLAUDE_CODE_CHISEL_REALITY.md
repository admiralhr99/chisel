# CLAUDE CODE INSTRUCTIONS: Add Reality Authentication to Chisel

## 🎯 MISSION
Modify chisel (lightweight Go tunnel) to add:
1. **uTLS fingerprinting** - Make TLS traffic look like Chrome browser
2. **Reality authentication** - X25519 ECDH + AES-GCM session verification
3. **Anti-probing** - Forward unauthenticated traffic to real website

**Result:** DPI-resistant tunnel that bypasses Iran's firewall by appearing as normal HTTPS to legitimate websites.

---

## 📋 WHY CHISEL?

Chisel is **perfect for modification**:
- **Small codebase**: ~350 lines total (client ~200, server ~150)
- **Clean architecture**: Separate client/server, clear interfaces
- **Already uses HTTPS**: WebSocket over TLS (just needs better TLS fingerprint)
- **No complex protocol**: Simple tunnel, easy to add auth layer

Compare to alternatives:
- rathole: ~5000+ lines, complex Rust
- xray-core: ~50,000+ lines, massive dependency tree
- v2ray: Even more complex

---

## 🚀 IMPLEMENTATION TASKS

### TASK 1: Repository Setup

```bash
# Clone chisel
git clone https://github.com/jpillora/chisel.git
cd chisel

# Create feature branch
git checkout -b reality-auth

# Verify structure
ls -la
# Expected: client/, server/, share/, main.go
```

**Verify chisel compiles:**
```bash
go build -o chisel .
./chisel --help
```

---

### TASK 2: Add Dependencies to go.mod

**File:** `go.mod`

**Add these dependencies:**
```go
require (
    // Existing chisel dependencies...
    
    // uTLS for browser fingerprinting
    github.com/refraction-networking/utls v1.6.1
    
    // Reality authentication
    golang.org/x/crypto v0.18.0  // For HKDF, X25519
    
    // Existing: github.com/gorilla/websocket (already in chisel)
)
```

**Verify dependencies:**
```bash
go mod tidy
go mod download
```

---

### TASK 3: Create Reality Authentication Package

**File:** `share/reality/reality.go` (NEW FILE)

**Purpose:** Implement Reality protocol authentication layer

**Requirements:**
1. X25519 ECDH key exchange
2. HKDF-SHA256 key derivation (info="REALITY")
3. AES-GCM session ID encryption
4. 32-byte session ID structure
5. Timestamp validation (±30 seconds)

**Session ID Structure (32 bytes):**
```
Byte 0-2:   Version (0x00, 0x01, 0x00)
Byte 3:     Reserved (0x00)
Byte 4-7:   Unix timestamp (big-endian uint32)
Byte 8-15:  ShortId (user configurable, can be empty)
Byte 16-31: Random padding
```

**Implement these functions:**

```go
package reality

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "time"
    
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
    "crypto/sha256"
    "io"
)

// Config holds Reality authentication configuration
type Config struct {
    PrivateKey [32]byte  // Server's X25519 private key
    PublicKey  [32]byte  // Server's X25519 public key (client uses this)
    ShortId    []byte    // Optional identifier (0-8 bytes)
}

// GenerateKeyPair generates X25519 keypair for Reality
func GenerateKeyPair() (private, public [32]byte, err error) {
    // Generate random private key
    // Derive public key using curve25519
    // Return both
}

// Client-side: Create authenticated session ID
func CreateSessionID(serverPublicKey [32]byte, shortId []byte) (sessionID [32]byte, clientPrivate [32]byte, err error) {
    // 1. Generate client X25519 keypair
    // 2. Compute shared secret via ECDH
    // 3. Derive AuthKey using HKDF-SHA256 with info="REALITY"
    // 4. Build session ID structure
    // 5. Encrypt bytes 0-15 with AES-GCM using AuthKey
    // 6. Return session ID
}

// Server-side: Verify session ID
func VerifySessionID(sessionID [32]byte, clientPublicKey [32]byte, serverPrivate [32]byte, shortId []byte) error {
    // 1. Compute shared secret using server private + client public
    // 2. Derive AuthKey using HKDF-SHA256
    // 3. Decrypt session ID bytes 0-15
    // 4. Verify version bytes (0x00, 0x01, 0x00)
    // 5. Verify timestamp (±30 seconds)
    // 6. Verify shortId matches
    // 7. Return error if verification fails
}

// Helper: Derive authentication key from shared secret
func deriveAuthKey(sharedSecret [32]byte) ([]byte, error) {
    // HKDF-SHA256 with salt=nil, info="REALITY"
    // Extract 32 bytes
}
```

**Implementation notes:**
- Use `crypto/rand.Read()` for random generation
- Use `curve25519.X25519()` for ECDH
- Use `hkdf.New(sha256.New, secret, nil, []byte("REALITY"))`
- Use `aes.NewCipher()` + `cipher.NewGCM()` for encryption
- Timestamp tolerance: ±30 seconds to handle clock skew

---

### TASK 4: Modify Client to Use uTLS

**File:** `client/client.go`

**Current behavior:** Uses standard `crypto/tls` which has identifiable fingerprint

**Required changes:**

**Step 4.1 - Add imports:**
```go
import (
    // Existing imports...
    
    tls "github.com/refraction-networking/utls"  // Replace crypto/tls
    "github.com/yourusername/chisel/share/reality"
)
```

**Step 4.2 - Add Reality config to Client struct:**

Find the `Client` struct and add:
```go
type Client struct {
    // Existing fields...
    
    RealityEnabled    bool
    RealityPublicKey  [32]byte
    RealityShortId    []byte
    RealitySessionID  [32]byte
}
```

**Step 4.3 - Modify TLS dialer to use uTLS:**

Find the function that creates TLS connection (likely in `client.go` where websocket dials).

**Replace this pattern:**
```go
// OLD CODE
tlsConfig := &tls.Config{
    ServerName: host,
}
conn, err := tls.Dial("tcp", addr, tlsConfig)
```

**With this:**
```go
// NEW CODE with uTLS
tcpConn, err := net.Dial("tcp", addr)
if err != nil {
    return nil, err
}

tlsConfig := &tls.Config{
    ServerName: host,
    InsecureSkipVerify: false,  // Keep certificate validation
}

// Use Chrome fingerprint for maximum stealth
tlsConn := tls.UClient(tcpConn, tlsConfig, tls.HelloChrome_Auto)

// If Reality is enabled, inject session ID into TLS session
if c.RealityEnabled {
    // Generate session ID
    sessionID, _, err := reality.CreateSessionID(c.RealityPublicKey, c.RealityShortId)
    if err != nil {
        return nil, err
    }
    c.RealitySessionID = sessionID
    
    // Set TLS session ID (this is how Reality auth is transmitted)
    tlsConn.SetSessionCache(tls.NewLRUClientSessionCache(0))
    // Note: Reality auth happens at application layer via custom headers
}

err = tlsConn.Handshake()
if err != nil {
    return nil, err
}
```

**Step 4.4 - Add Reality authentication to WebSocket headers:**

Find where WebSocket connection is established (likely using `gorilla/websocket.Dialer`).

**Add custom header with Reality session ID:**
```go
// Add to websocket request headers
headers := http.Header{}
if c.RealityEnabled {
    // Encode session ID as base64 and send in custom header
    sessionIDEncoded := base64.StdEncoding.EncodeToString(c.RealitySessionID[:])
    headers.Add("X-Session-Id", sessionIDEncoded)
}

dialer := &websocket.Dialer{
    NetDial: func(network, addr string) (net.Conn, error) {
        return tlsConn, nil  // Use our uTLS connection
    },
}

wsConn, _, err := dialer.Dial(wsURL, headers)
```

---

### TASK 5: Modify Server to Verify Reality Authentication

**File:** `server/server.go`

**Step 5.1 - Add Reality config to Server struct:**

```go
type Server struct {
    // Existing fields...
    
    RealityEnabled    bool
    RealityPrivateKey [32]byte
    RealityShortId    []byte
    FallbackURL       string  // URL to proxy unauthenticated requests
}
```

**Step 5.2 - Add authentication middleware:**

Create new function in `server/server.go`:

```go
func (s *Server) authenticateReality(w http.ResponseWriter, r *http.Request) bool {
    if !s.RealityEnabled {
        return true  // Reality disabled, allow all
    }
    
    // Extract session ID from header
    sessionIDEncoded := r.Header.Get("X-Session-Id")
    if sessionIDEncoded == "" {
        s.proxyToFallback(w, r)
        return false
    }
    
    sessionIDBytes, err := base64.StdEncoding.DecodeString(sessionIDEncoded)
    if err != nil || len(sessionIDBytes) != 32 {
        s.proxyToFallback(w, r)
        return false
    }
    
    var sessionID [32]byte
    copy(sessionID[:], sessionIDBytes)
    
    // Extract client public key from TLS connection
    // (This is simplified - in production, client sends public key in another header)
    clientPubKeyHeader := r.Header.Get("X-Client-Pubkey")
    if clientPubKeyHeader == "" {
        s.proxyToFallback(w, r)
        return false
    }
    
    clientPubKeyBytes, _ := base64.StdEncoding.DecodeString(clientPubKeyHeader)
    var clientPubKey [32]byte
    copy(clientPubKey[:], clientPubKeyBytes)
    
    // Verify Reality authentication
    err = reality.VerifySessionID(sessionID, clientPubKey, s.RealityPrivateKey, s.RealityShortId)
    if err != nil {
        log.Printf("Reality auth failed: %v", err)
        s.proxyToFallback(w, r)
        return false
    }
    
    return true  // Authentication succeeded
}

// Proxy unauthenticated requests to real website (anti-probing)
func (s *Server) proxyToFallback(w http.ResponseWriter, r *http.Request) {
    if s.FallbackURL == "" {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    
    // Create proxy request to fallback URL
    proxyURL := s.FallbackURL + r.URL.Path
    proxyReq, _ := http.NewRequest(r.Method, proxyURL, r.Body)
    
    // Copy headers
    for k, v := range r.Header {
        proxyReq.Header[k] = v
    }
    
    // Forward request
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(proxyReq)
    if err != nil {
        http.Error(w, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    // Copy response
    for k, v := range resp.Header {
        w.Header()[k] = v
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

**Step 5.3 - Integrate authentication into WebSocket handler:**

Find the WebSocket upgrade handler and add authentication check:

```go
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Add authentication check BEFORE upgrading to WebSocket
    if !s.authenticateReality(w, r) {
        return  // Authentication failed, already handled by proxyToFallback
    }
    
    // Existing WebSocket upgrade code...
    upgrader := websocket.Upgrader{}
    conn, err := upgrader.Upgrade(w, r, nil)
    // ... rest of existing code
}
```

---

### TASK 6: Add CLI Flags for Reality Configuration

**File:** `main.go`

**Client flags:**
```go
// Add to client command flags
var (
    realityPubkey  string  // Base64 encoded public key
    realityShortId string  // Optional short ID
)

clientCmd.Flags().StringVar(&realityPubkey, "reality-pubkey", "", 
    "Reality server public key (base64)")
clientCmd.Flags().StringVar(&realityShortId, "reality-shortid", "", 
    "Reality short ID (optional)")
```

**Server flags:**
```go
// Add to server command flags
var (
    realityPrivkey  string  // Base64 encoded private key
    realityShortId  string  // Optional short ID
    realityFallback string  // Fallback URL for unauthenticated requests
)

serverCmd.Flags().StringVar(&realityPrivkey, "reality-privkey", "", 
    "Reality private key (base64)")
serverCmd.Flags().StringVar(&realityShortId, "reality-shortid", "", 
    "Reality short ID (optional)")
serverCmd.Flags().StringVar(&realityFallback, "reality-fallback", "https://www.microsoft.com", 
    "Fallback URL for unauthenticated requests")
```

**Add key generation command:**
```go
// Add new command for key generation
var keygenCmd = &cobra.Command{
    Use:   "genkey",
    Short: "Generate Reality keypair",
    Run: func(cmd *cobra.Command, args []string) {
        priv, pub, err := reality.GenerateKeyPair()
        if err != nil {
            log.Fatal(err)
        }
        
        fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
        fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(pub[:]))
        fmt.Println("\nServer: Use --reality-privkey with private key")
        fmt.Println("Client: Use --reality-pubkey with public key")
    },
}

func init() {
    rootCmd.AddCommand(keygenCmd)
}
```

---

### TASK 7: Update Client Initialization

**File:** `client/client.go`

**Modify client creation to parse Reality config:**

```go
func NewClient(config *ClientConfig) (*Client, error) {
    client := &Client{
        // Existing initialization...
    }
    
    // Parse Reality configuration
    if config.RealityPubkey != "" {
        client.RealityEnabled = true
        
        pubkeyBytes, err := base64.StdEncoding.DecodeString(config.RealityPubkey)
        if err != nil || len(pubkeyBytes) != 32 {
            return nil, errors.New("invalid reality public key")
        }
        copy(client.RealityPublicKey[:], pubkeyBytes)
        
        if config.RealityShortId != "" {
            client.RealityShortId = []byte(config.RealityShortId)
        }
    }
    
    return client, nil
}
```

---

### TASK 8: Update Server Initialization

**File:** `server/server.go`

```go
func NewServer(config *ServerConfig) (*Server, error) {
    server := &Server{
        // Existing initialization...
    }
    
    // Parse Reality configuration
    if config.RealityPrivkey != "" {
        server.RealityEnabled = true
        
        privkeyBytes, err := base64.StdEncoding.DecodeString(config.RealityPrivkey)
        if err != nil || len(privkeyBytes) != 32 {
            return nil, errors.New("invalid reality private key")
        }
        copy(server.RealityPrivateKey[:], privkeyBytes)
        
        if config.RealityShortId != "" {
            server.RealityShortId = []byte(config.RealityShortId)
        }
        
        server.FallbackURL = config.RealityFallback
    }
    
    return server, nil
}
```

---

### TASK 9: Client Must Send Public Key

**Important fix:** Client needs to send its ephemeral public key to server.

**Modify `client/client.go` WebSocket connection:**

```go
// When creating WebSocket connection, also send client public key
sessionID, clientPrivateKey, err := reality.CreateSessionID(c.RealityPublicKey, c.RealityShortId)
if err != nil {
    return nil, err
}

// Derive client public key from private key
var clientPublicKey [32]byte
curve25519.ScalarBaseMult(&clientPublicKey, &clientPrivateKey)

// Add both session ID and client public key to headers
headers := http.Header{}
headers.Add("X-Session-Id", base64.StdEncoding.EncodeToString(sessionID[:]))
headers.Add("X-Client-Pubkey", base64.StdEncoding.EncodeToString(clientPublicKey[:]))
```

---

### TASK 10: Build and Test

**Build:**
```bash
go build -o chisel-reality .
```

**Generate keys:**
```bash
./chisel-reality genkey
# Save the output - you'll need both keys
```

**Test server:**
```bash
./chisel-reality server \
  --port 443 \
  --reality-privkey "PASTE_PRIVATE_KEY" \
  --reality-shortid "myshortid" \
  --reality-fallback "https://www.microsoft.com"
```

**Test client:**
```bash
./chisel-reality client \
  https://your-server.com:443 \
  8080:localhost:8080 \
  --reality-pubkey "PASTE_PUBLIC_KEY" \
  --reality-shortid "myshortid"
```

**Verify authentication:**
```bash
# Authenticated request should work
curl -x socks5://localhost:1080 https://google.com

# Unauthenticated request should proxy to fallback
curl https://your-server.com:443
# Should return Microsoft's website
```

---

## ✅ VERIFICATION CHECKLIST

- [ ] `go build` succeeds without errors
- [ ] `chisel-reality genkey` generates keypair
- [ ] Server starts with Reality flags
- [ ] Client connects with valid credentials
- [ ] Client with wrong credentials gets forwarded to fallback
- [ ] Direct HTTPS request to server returns fallback website
- [ ] Traffic capture shows Chrome TLS fingerprint (not Go)
- [ ] Session ID structure is exactly 32 bytes
- [ ] Timestamp validation works (±30 seconds)

---

## 🚨 COMMON ISSUES

### "cannot find package crypto/tls"
**Solution:** Import path conflicts. Make sure:
```go
import tls "github.com/refraction-networking/utls"
```
NOT:
```go
import "crypto/tls"
```

### "invalid session ID length"
**Solution:** Session ID must be exactly 32 bytes. Check:
```go
var sessionID [32]byte  // Fixed-size array, not slice
```

### "authentication always fails"
**Solution:** Check that:
1. Client and server use same ShortId
2. System clocks are synchronized (within 30 seconds)
3. Public/private keys match (public derived from private)

### "TLS handshake fails"
**Solution:** 
```go
// Make sure you call Handshake() before using connection
err = tlsConn.Handshake()
if err != nil {
    return nil, err
}
```

---

## 📊 FILE CHANGE SUMMARY

| File | Action | Lines Changed |
|------|--------|---------------|
| `go.mod` | Modify | +3 dependencies |
| `share/reality/reality.go` | Create | ~400 lines NEW |
| `client/client.go` | Modify | ~50 lines changed |
| `server/server.go` | Modify | ~100 lines changed |
| `main.go` | Modify | ~30 lines added |

**Total new code:** ~400 lines (Reality package)  
**Total modifications:** ~180 lines (client/server integration)  
**Total:** ~580 lines for full Reality support

This is **MUCH simpler** than implementing a new tunnel from scratch or modifying rathole.

---

## 🎯 SUCCESS METRICS

Implementation successful when:

1. **Compiles cleanly** - No Go errors
2. **Keys generate** - `genkey` command works
3. **Authentication works** - Valid clients connect
4. **Anti-probing works** - Invalid requests go to fallback
5. **TLS fingerprint** - Traffic looks like Chrome (verify with Wireshark)
6. **Code quality** - Follows chisel's clean style

---

## 💡 OPTIMIZATION IDEAS (OPTIONAL)

After basic implementation works:

1. **Multiple ShortIds** - Support array of ShortIds for multiple users
2. **Key rotation** - Periodic key regeneration
3. **Rate limiting** - Prevent brute force on authentication
4. **Logging** - Structured logs for auth attempts
5. **Metrics** - Track success/failure rates

---

## 📚 REFERENCES

- Chisel source: https://github.com/jpillora/chisel
- uTLS library: https://github.com/refraction-networking/utls
- Reality protocol: https://github.com/XTLS/Xray-core (transport/internet/reality/)
- HKDF spec: RFC 5869
- X25519 spec: RFC 7748

---

**Good luck! This will create a powerful DPI-resistant tunnel for Iran.** 🚀
