# Testing Guide: Chisel + Reality Authentication

## Testing Strategy

This guide covers testing your Reality-enhanced chisel implementation at multiple levels:
1. Unit tests (crypto functions)
2. Integration tests (client-server auth)
3. Security tests (anti-probing, fingerprinting)
4. Performance tests
5. Real-world deployment tests

---

## Phase 1: Crypto Function Unit Tests

### Test X25519 Key Generation

```go
// File: share/reality/reality_test.go

package reality

import (
    "testing"
    "bytes"
)

func TestGenerateKeyPair(t *testing.T) {
    priv1, pub1, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("Failed to generate keypair: %v", err)
    }
    
    // Keys should be 32 bytes
    if len(priv1) != 32 || len(pub1) != 32 {
        t.Errorf("Invalid key length")
    }
    
    // Multiple generations should produce different keys
    priv2, pub2, _ := GenerateKeyPair()
    if bytes.Equal(priv1[:], priv2[:]) {
        t.Errorf("Generated identical private keys (should be random)")
    }
    if bytes.Equal(pub1[:], pub2[:]) {
        t.Errorf("Generated identical public keys (should be random)")
    }
}

func TestECDHSharedSecret(t *testing.T) {
    // Generate two keypairs
    alicePriv, alicePub, _ := GenerateKeyPair()
    bobPriv, bobPub, _ := GenerateKeyPair()
    
    // Compute shared secrets
    aliceShared := computeSharedSecret(alicePriv, bobPub)
    bobShared := computeSharedSecret(bobPriv, alicePub)
    
    // Both should compute same shared secret
    if !bytes.Equal(aliceShared[:], bobShared[:]) {
        t.Errorf("ECDH failed: shared secrets don't match")
    }
}
```

### Test HKDF Key Derivation

```go
func TestHKDF(t *testing.T) {
    // Known test vector
    var sharedSecret [32]byte
    for i := 0; i < 32; i++ {
        sharedSecret[i] = byte(i)
    }
    
    authKey1, _ := deriveAuthKey(sharedSecret)
    authKey2, _ := deriveAuthKey(sharedSecret)
    
    // Same input should produce same output
    if !bytes.Equal(authKey1[:], authKey2[:]) {
        t.Errorf("HKDF not deterministic")
    }
    
    // Output should be 32 bytes
    if len(authKey1) != 32 {
        t.Errorf("AuthKey wrong length: got %d, want 32", len(authKey1))
    }
}
```

### Test Session ID Structure

```go
func TestSessionIDFormat(t *testing.T) {
    serverPriv, serverPub, _ := GenerateKeyPair()
    shortId := []byte("test")
    
    sessionID, clientPriv, err := CreateSessionID(serverPub, shortId)
    if err != nil {
        t.Fatalf("Failed to create session ID: %v", err)
    }
    
    // Session ID should be exactly 32 bytes
    if len(sessionID) != 32 {
        t.Errorf("SessionID wrong length: got %d, want 32", len(sessionID))
    }
    
    // Derive client public key
    var clientPub [32]byte
    curve25519.ScalarBaseMult(&clientPub, &clientPriv)
    
    // Server should verify successfully
    err = VerifySessionID(sessionID, clientPub, serverPriv, shortId)
    if err != nil {
        t.Errorf("Valid session ID failed verification: %v", err)
    }
}
```

**Run unit tests:**
```bash
go test -v ./share/reality/
```

---

## Phase 2: Integration Tests

### Test Full Client-Server Authentication

```bash
# Terminal 1: Start server
./chisel-reality server \
  --port 18080 \
  --reality-privkey "GENERATED_PRIVATE_KEY" \
  --reality-shortid "test" \
  --reality-fallback "https://www.microsoft.com"

# Terminal 2: Start client
./chisel-reality client https://localhost:18080 8080:localhost:8080 \
  --reality-pubkey "GENERATED_PUBLIC_KEY" \
  --reality-shortid "test"

# Terminal 3: Test connection
curl -x socks5://localhost:1080 https://google.com
# Should succeed
```

---

## Phase 3: TLS Fingerprint Testing

### Verify uTLS Chrome Fingerprint

```bash
# Capture client TLS handshake
sudo tcpdump -i lo -w client-handshake.pcap port 18080 &

# Start your client
./chisel-reality client https://localhost:18080 8080:localhost:8080 \
  --reality-pubkey "YOUR_PUBKEY"

# Stop capture
sudo killall tcpdump

# Analyze
tshark -r client-handshake.pcap -Y "ssl.handshake.type == 1" -V

# Should show Chrome-like cipher suites and extensions
```

---

## Phase 4: Anti-Probing Tests

### Test Fallback Behavior

```bash
# Test 1: Direct HTTPS request (no auth headers)
curl -v https://your-server.com:443/
# Expected: Returns Microsoft.com content

# Test 2: Request with invalid auth
curl -v https://your-server.com:443/ \
  -H "X-Session-Id: InvalidBase64String"
# Expected: Returns fallback website

# Test 3: Valid auth
./chisel-reality client https://your-server.com:443 8080:localhost:80 \
  --reality-pubkey "VALID_KEY"
# Expected: Tunnel works
```

---

## Testing Checklist

### Pre-Deployment
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] TLS fingerprint matches Chrome
- [ ] Anti-probing returns fallback website
- [ ] No information leakage in responses

### Deployment
- [ ] Server starts on port 443
- [ ] Direct HTTPS request returns fallback
- [ ] Client connects with valid credentials
- [ ] Client with wrong credentials gets fallback
- [ ] Traffic shows only TLS ApplicationData

---

**When all tests pass, you're ready for production!** 🎉
