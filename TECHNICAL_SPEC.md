# Reality Protocol Technical Specification

## Overview

Reality is an authentication protocol designed to make proxy traffic indistinguishable from legitimate HTTPS connections. It uses X25519 ECDH key exchange with AES-GCM encryption to authenticate clients without visible protocol signatures.

---

## Cryptographic Primitives

### 1. X25519 Elliptic Curve Diffie-Hellman (ECDH)

**Purpose:** Generate shared secret between client and server

**Key Generation:**
```
Private Key: 32 random bytes
Public Key: X25519(Private Key, Basepoint)
```

**Shared Secret Derivation:**
```
Client: SharedSecret = X25519(ClientPrivate, ServerPublic)
Server: SharedSecret = X25519(ServerPrivate, ClientPublic)

Result: Both parties have identical 32-byte shared secret
```

**Go Implementation:**
```go
import "golang.org/x/crypto/curve25519"

// Generate keypair
var private [32]byte
rand.Read(private[:])
public := curve25519.ScalarBaseMult(&private)

// Compute shared secret
sharedSecret := curve25519.X25519(privateKey, peerPublicKey)
```

### 2. HKDF-SHA256 Key Derivation

**Purpose:** Derive authentication key from shared secret

**Parameters:**
- Hash: SHA-256
- Salt: nil (no salt)
- Info: "REALITY" (UTF-8 bytes)
- Output length: 32 bytes

**Go Implementation:**
```go
import (
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
    "io"
)

func deriveAuthKey(sharedSecret [32]byte) ([32]byte, error) {
    hkdf := hkdf.New(sha256.New, sharedSecret[:], nil, []byte("REALITY"))
    
    var authKey [32]byte
    _, err := io.ReadFull(hkdf, authKey[:])
    return authKey, err
}
```

### 3. AES-GCM Encryption

**Purpose:** Encrypt/decrypt session ID for authentication

**Parameters:**
- Key: 32-byte AuthKey from HKDF
- Nonce: Random 12 bytes
- Additional Data: None
- Plaintext: First 16 bytes of session ID
- Tag: Appended to ciphertext (16 bytes)

**Go Implementation:**
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

func encryptSessionID(authKey [32]byte, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(authKey[:])
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

func decryptSessionID(authKey [32]byte, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(authKey[:])
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    return plaintext, err
}
```

---

## Session ID Structure

### Binary Layout (32 bytes total)

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0      | 1    | Version[0]     | 0x00 (Xray version major)
1      | 1    | Version[1]     | 0x01 (Xray version minor)
2      | 1    | Version[2]     | 0x00 (Xray version patch)
3      | 1    | Reserved       | 0x00 (reserved for future use)
4      | 4    | Timestamp      | Unix timestamp (big-endian uint32)
8      | 8    | ShortId        | User-defined identifier (can be zero)
16     | 16   | Padding        | Random bytes for full 32-byte size
```

**Important:** Only bytes 0-15 are encrypted. Bytes 16-31 remain unencrypted (random padding).

### Go Struct Representation:

```go
type SessionID struct {
    Version   [3]byte  // [0x00, 0x01, 0x00]
    Reserved  byte     // 0x00
    Timestamp uint32   // Unix timestamp
    ShortId   [8]byte  // User identifier
    Padding   [16]byte // Random padding
}

func (s *SessionID) MarshalBinary() []byte {
    buf := make([]byte, 32)
    copy(buf[0:3], s.Version[:])
    buf[3] = s.Reserved
    binary.BigEndian.PutUint32(buf[4:8], s.Timestamp)
    copy(buf[8:16], s.ShortId[:])
    copy(buf[16:32], s.Padding[:])
    return buf
}
```

---

## Authentication Flow

### Client Side (Session ID Creation)

```
1. Generate ephemeral X25519 keypair (ClientPrivate, ClientPublic)
2. Compute SharedSecret = X25519(ClientPrivate, ServerPublic)
3. Derive AuthKey = HKDF-SHA256(SharedSecret, salt=nil, info="REALITY")
4. Build SessionID structure:
   - Version: [0x00, 0x01, 0x00]
   - Reserved: 0x00
   - Timestamp: Current Unix time (uint32)
   - ShortId: User-provided identifier (or zeros)
   - Padding: 16 random bytes
5. Encrypt bytes 0-15 of SessionID with AES-GCM using AuthKey
6. Send SessionID (32 bytes) + ClientPublic (32 bytes) to server
```

### Server Side (Session ID Verification)

```
1. Receive SessionID (32 bytes) + ClientPublic (32 bytes)
2. Compute SharedSecret = X25519(ServerPrivate, ClientPublic)
3. Derive AuthKey = HKDF-SHA256(SharedSecret, salt=nil, info="REALITY")
4. Decrypt bytes 0-15 of SessionID using AuthKey
5. Verify decrypted data:
   a. Version == [0x00, 0x01, 0x00]
   b. Reserved == 0x00
   c. Timestamp within ±30 seconds of current time
   d. ShortId matches expected value (if configured)
6. If all checks pass: Authentication successful
7. If any check fails: Forward request to fallback website
```

---

## Timestamp Validation

**Purpose:** Prevent replay attacks

**Algorithm:**
```go
func verifyTimestamp(sessionTimestamp uint32) bool {
    now := uint32(time.Now().Unix())
    diff := int64(now) - int64(sessionTimestamp)
    
    // Allow ±30 seconds for clock skew
    if diff < -30 || diff > 30 {
        return false
    }
    return true
}
```

**Clock Synchronization:**
- Client and server must have synchronized clocks
- NTP recommended for both VPS servers
- Allow 30-second tolerance for network delays

---

## ShortId Usage

**Purpose:** Multiple users on single server with different identifiers

**Format:**
- Length: 0-8 bytes (can be empty)
- Encoding: UTF-8 string → bytes
- Common values: "", "user1", "12345678"

**Server configuration:**
```go
// Single ShortId (simple)
server.ShortId = []byte("myshortid")

// Multiple ShortIds (advanced - optional enhancement)
server.AllowedShortIds = [][]byte{
    []byte("user1"),
    []byte("user2"),
    []byte(""),  // Empty ShortId allowed
}
```

---

## Anti-Probing Mechanism

**Threat Model:** Active probing by censors

**Defense:** Unauthenticated requests appear as legitimate website traffic

**Implementation:**

```go
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
    sessionID := extractSessionID(r)
    clientPubKey := extractClientPubKey(r)
    
    // Attempt authentication
    err := reality.VerifySessionID(sessionID, clientPubKey, s.PrivateKey, s.ShortId)
    
    if err != nil {
        // Authentication failed - proxy to fallback website
        s.proxyToFallback(w, r)
        return
    }
    
    // Authentication succeeded - handle tunnel request
    s.handleTunnel(w, r)
}

func (s *Server) proxyToFallback(w http.ResponseWriter, r *http.Request) {
    // Create identical request to real website
    fallbackURL := s.FallbackURL + r.URL.Path
    
    proxyReq, _ := http.NewRequest(r.Method, fallbackURL, r.Body)
    
    // Copy all headers to look authentic
    for k, v := range r.Header {
        if !strings.HasPrefix(k, "X-") {  // Skip our custom headers
            proxyReq.Header[k] = v
        }
    }
    
    // Forward request to real website
    resp, err := http.DefaultClient.Do(proxyReq)
    if err != nil {
        http.Error(w, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    // Copy response back to client
    for k, v := range resp.Header {
        w.Header()[k] = v
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

**Result:** DPI systems see valid HTTPS responses from legitimate websites when probing.

---

## Wire Protocol (HTTP Headers)

Reality authentication is transmitted via custom HTTP headers in WebSocket upgrade request:

```
GET / HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
X-Session-Id: <base64-encoded-32-bytes>
X-Client-Pubkey: <base64-encoded-32-bytes>
```

**Header Definitions:**

| Header | Size | Encoding | Purpose |
|--------|------|----------|---------|
| X-Session-Id | 44 chars | Base64 | Encrypted session ID (32 bytes → 44 chars) |
| X-Client-Pubkey | 44 chars | Base64 | Client's ephemeral public key (32 bytes → 44 chars) |

**Base64 Encoding:**
```go
sessionIDEncoded := base64.StdEncoding.EncodeToString(sessionID[:])
// Length: 32 bytes → 44 characters base64
```

---

## Security Properties

### ✅ Strengths

1. **No visible protocol signature** - Uses standard TLS + HTTP
2. **Perfect forward secrecy** - Ephemeral X25519 keys per connection
3. **Replay attack prevention** - Timestamp validation
4. **Active probe resistance** - Returns legitimate website content
5. **No secret in certificate** - Unlike traditional TLS, no need for real certificates

### ⚠️ Limitations

1. **Clock dependency** - Requires synchronized time (±30 seconds)
2. **No mutual authentication** - Only server authenticates to client (client trusts server public key)
3. **Traffic analysis vulnerability** - Volume/timing analysis can still detect heavy proxy usage
4. **IP-based blocking** - If server IP is identified, entire IP gets blocked regardless of protocol

---

## Error Handling

### Authentication Errors

```go
var (
    ErrInvalidSessionID     = errors.New("invalid session ID structure")
    ErrTimestampExpired     = errors.New("timestamp outside valid range")
    ErrShortIdMismatch      = errors.New("shortId does not match")
    ErrDecryptionFailed     = errors.New("failed to decrypt session ID")
    ErrInvalidVersion       = errors.New("invalid protocol version")
)
```

### Error Responses

**Client-facing errors:** Never reveal authentication failure details
```go
// BAD - reveals auth failure
http.Error(w, "Authentication failed: invalid timestamp", 401)

// GOOD - indistinguishable from real website
s.proxyToFallback(w, r)  // Returns Microsoft.com content
```

---

## Performance Characteristics

**Computational Cost per Connection:**

| Operation | Time (approx) | Notes |
|-----------|---------------|-------|
| X25519 ECDH | ~50μs | Very fast on modern CPUs |
| HKDF-SHA256 | ~10μs | Fast hash operation |
| AES-GCM encrypt | ~5μs | Hardware accelerated |
| Total overhead | ~65μs | Negligible for network traffic |

**Memory:**
- SessionID: 32 bytes
- Keys: 64 bytes (private + public)
- Shared secret: 32 bytes
- **Total per connection:** ~128 bytes

**Scalability:**
- Server can handle 10,000+ auth/sec on single core
- No state maintained after authentication
- Stateless design enables horizontal scaling

---

## Testing Vectors

### Test Case 1: Valid Authentication

```
Server Private: 0x60...3f (32 bytes)
Server Public:  0xa1...2e (32 bytes)

Client Private: 0x70...4a (32 bytes)
Client Public:  0xb2...3f (32 bytes)

Shared Secret:  0xc3...5b (32 bytes)
AuthKey (HKDF): 0xd4...6c (32 bytes)

SessionID (plaintext):
  Version:    [0x00, 0x01, 0x00]
  Reserved:   0x00
  Timestamp:  1704067200 (2024-01-01 00:00:00 UTC)
  ShortId:    "testuser" (0x74657374757365720000)
  Padding:    Random

Expected: Authentication SUCCEEDS
```

### Test Case 2: Expired Timestamp

```
Same as Test Case 1, but:
Timestamp: 1704000000 (67200 seconds old - ~18 hours)

Expected: Authentication FAILS (timestamp expired)
```

### Test Case 3: Wrong ShortId

```
Same as Test Case 1, but:
SessionID ShortId: "wrongusr"
Server expects:    "testuser"

Expected: Authentication FAILS (shortId mismatch)
```

---

## Implementation Checklist

- [ ] X25519 key generation
- [ ] ECDH shared secret computation
- [ ] HKDF-SHA256 key derivation
- [ ] AES-GCM encryption/decryption
- [ ] Session ID structure marshaling
- [ ] Timestamp validation (±30s)
- [ ] ShortId comparison
- [ ] Base64 encoding/decoding
- [ ] HTTP header extraction
- [ ] Anti-probing fallback proxy
- [ ] Error handling (no info leakage)
- [ ] Unit tests for crypto operations
- [ ] Integration tests for full flow

---

## References

- **X25519**: RFC 7748 (Elliptic Curves for Security)
- **HKDF**: RFC 5869 (HMAC-based Extract-and-Expand Key Derivation Function)
- **AES-GCM**: NIST SP 800-38D (Galois/Counter Mode)
- **Reality Protocol**: XTLS Xray-core implementation
  - https://github.com/XTLS/Xray-core/tree/main/transport/internet/reality

---

**This specification provides everything needed to implement Reality authentication correctly.** 🔐
