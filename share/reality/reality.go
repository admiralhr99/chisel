// Package reality implements Reality authentication protocol for DPI-resistant tunneling.
// It provides X25519 ECDH key exchange with AES-CTR encryption and HMAC verification.
package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// SessionIDSize is the size of the Reality session ID in bytes
	SessionIDSize = 32

	// KeySize is the size of X25519 keys in bytes
	KeySize = 32

	// MaxShortIDSize is the maximum size of the short ID
	MaxShortIDSize = 8

	// NonceSize for CTR mode
	NonceSize = 12

	// MACSize is the truncated MAC size
	MACSize = 4

	// PlaintextSize is the size of session metadata
	PlaintextSize = 16

	// TimestampTolerance is the allowed clock skew for timestamp validation
	TimestampTolerance = 30 * time.Second

	// Version bytes for session ID
	VersionMajor = 0x00
	VersionMinor = 0x01
	VersionPatch = 0x00
)

var (
	// ErrInvalidSessionID indicates the session ID format is invalid
	ErrInvalidSessionID = errors.New("reality: invalid session ID")

	// ErrInvalidVersion indicates the session ID version is not supported
	ErrInvalidVersion = errors.New("reality: invalid version")

	// ErrTimestampExpired indicates the session ID timestamp is outside tolerance
	ErrTimestampExpired = errors.New("reality: timestamp expired")

	// ErrShortIDMismatch indicates the short ID does not match
	ErrShortIDMismatch = errors.New("reality: short ID mismatch")

	// ErrInvalidKeySize indicates the key size is incorrect
	ErrInvalidKeySize = errors.New("reality: invalid key size")

	// ErrDecryptionFailed indicates decryption or MAC verification failed
	ErrDecryptionFailed = errors.New("reality: decryption failed")

	// hkdfInfo is the info parameter for HKDF key derivation
	hkdfInfo = []byte("REALITY")
)

// Config holds Reality authentication configuration
type Config struct {
	PrivateKey [KeySize]byte // Server's X25519 private key
	PublicKey  [KeySize]byte // Server's X25519 public key (client uses this)
	ShortID    []byte        // Optional identifier (0-8 bytes)
}

// GenerateKeyPair generates an X25519 keypair for Reality authentication.
// Returns the private key, public key, and any error encountered.
func GenerateKeyPair() (private, public [KeySize]byte, err error) {
	// Generate random private key
	_, err = rand.Read(private[:])
	if err != nil {
		return private, public, err
	}

	// Clamp private key for X25519 (per RFC 7748)
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	// Derive public key using curve25519 scalar base multiplication
	publicSlice, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return private, public, err
	}
	copy(public[:], publicSlice)

	return private, public, nil
}

// CreateSessionID creates an authenticated session ID for client-side use.
// It generates an ephemeral keypair, performs ECDH with the server's public key,
// and encrypts the session metadata using AES-CTR with HMAC.
//
// Session ID structure (32 bytes):
//   - Bytes 0-11:  Nonce
//   - Bytes 12-27: Encrypted metadata (version + timestamp + shortID)
//   - Bytes 28-31: Truncated HMAC
//
// Returns the 32-byte session ID, the client's ephemeral public key, and any error.
func CreateSessionID(serverPublicKey [KeySize]byte, shortID []byte) (sessionID [SessionIDSize]byte, clientPublic [KeySize]byte, err error) {
	// Validate and truncate short ID if needed
	if len(shortID) > MaxShortIDSize {
		shortID = shortID[:MaxShortIDSize]
	}

	// Generate ephemeral client keypair
	clientPrivate, clientPublic, err := GenerateKeyPair()
	if err != nil {
		return sessionID, clientPublic, err
	}

	// Compute shared secret via ECDH
	sharedSecret, err := curve25519.X25519(clientPrivate[:], serverPublicKey[:])
	if err != nil {
		return sessionID, clientPublic, err
	}

	// Derive authentication key using HKDF
	authKey, err := deriveAuthKey(sharedSecret)
	if err != nil {
		return sessionID, clientPublic, err
	}

	// Build session metadata plaintext (16 bytes)
	// Byte 0-2:   Version (0x00, 0x01, 0x00)
	// Byte 3:     Reserved (0x00)
	// Byte 4-7:   Unix timestamp (big-endian uint32)
	// Byte 8-15:  ShortId (padded with zeros)
	var plaintext [PlaintextSize]byte
	plaintext[0] = VersionMajor
	plaintext[1] = VersionMinor
	plaintext[2] = VersionPatch
	plaintext[3] = 0x00 // Reserved

	timestamp := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(plaintext[4:8], timestamp)
	copy(plaintext[8:16], shortID)

	// Encrypt and authenticate
	encrypted, err := encryptSessionData(authKey, plaintext[:])
	if err != nil {
		return sessionID, clientPublic, err
	}

	copy(sessionID[:], encrypted)
	return sessionID, clientPublic, nil
}

// VerifySessionID verifies a session ID received from a client.
// It performs ECDH using the server's private key and client's public key,
// then decrypts and validates the session metadata.
func VerifySessionID(sessionID [SessionIDSize]byte, clientPublicKey [KeySize]byte, serverPrivate [KeySize]byte, shortID []byte) error {
	// Validate and truncate short ID if needed
	if len(shortID) > MaxShortIDSize {
		shortID = shortID[:MaxShortIDSize]
	}

	// Compute shared secret via ECDH
	sharedSecret, err := curve25519.X25519(serverPrivate[:], clientPublicKey[:])
	if err != nil {
		return err
	}

	// Derive authentication key using HKDF
	authKey, err := deriveAuthKey(sharedSecret)
	if err != nil {
		return err
	}

	// Decrypt session data
	plaintext, err := decryptSessionData(authKey, sessionID[:])
	if err != nil {
		return err
	}

	// Verify version
	if plaintext[0] != VersionMajor || plaintext[1] != VersionMinor || plaintext[2] != VersionPatch {
		return ErrInvalidVersion
	}

	// Verify reserved byte
	if plaintext[3] != 0x00 {
		return ErrInvalidSessionID
	}

	// Verify timestamp (±30 seconds tolerance)
	timestamp := binary.BigEndian.Uint32(plaintext[4:8])
	now := uint32(time.Now().Unix())
	tolerance := uint32(TimestampTolerance.Seconds())

	// Handle underflow for timestamp comparison
	var timeDiff uint32
	if timestamp > now {
		timeDiff = timestamp - now
	} else {
		timeDiff = now - timestamp
	}
	if timeDiff > tolerance {
		return ErrTimestampExpired
	}

	// Verify short ID
	var expectedShortID [MaxShortIDSize]byte
	copy(expectedShortID[:], shortID)

	var receivedShortID [MaxShortIDSize]byte
	copy(receivedShortID[:], plaintext[8:16])

	if subtle.ConstantTimeCompare(expectedShortID[:], receivedShortID[:]) != 1 {
		return ErrShortIDMismatch
	}

	return nil
}

// deriveAuthKey derives an authentication key from the shared secret using HKDF-SHA256.
func deriveAuthKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, hkdfInfo)
	authKey := make([]byte, KeySize)
	_, err := io.ReadFull(hkdfReader, authKey)
	if err != nil {
		return nil, err
	}
	return authKey, nil
}

// encryptSessionData encrypts the 16-byte session plaintext using AES-CTR + truncated HMAC.
// Output: 12-byte nonce + 16-byte ciphertext + 4-byte truncated HMAC = 32 bytes
func encryptSessionData(authKey []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) != PlaintextSize {
		return nil, errors.New("plaintext must be 16 bytes")
	}

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Create CTR stream with nonce padded to block size
	ctrIV := make([]byte, aes.BlockSize)
	copy(ctrIV, nonce)
	stream := cipher.NewCTR(block, ctrIV)

	// Encrypt plaintext
	ciphertext := make([]byte, PlaintextSize)
	stream.XORKeyStream(ciphertext, plaintext)

	// Compute truncated HMAC over nonce + ciphertext
	mac := computeMAC(authKey, nonce, ciphertext)

	// Build 32-byte session ID
	result := make([]byte, SessionIDSize)
	copy(result[0:NonceSize], nonce)
	copy(result[NonceSize:NonceSize+PlaintextSize], ciphertext)
	copy(result[NonceSize+PlaintextSize:], mac[:MACSize])

	return result, nil
}

// decryptSessionData decrypts the session ID using AES-CTR and verifies the HMAC.
func decryptSessionData(authKey []byte, sessionData []byte) ([]byte, error) {
	if len(sessionData) != SessionIDSize {
		return nil, ErrInvalidSessionID
	}

	// Extract components
	nonce := sessionData[0:NonceSize]
	ciphertext := sessionData[NonceSize : NonceSize+PlaintextSize]
	receivedMAC := sessionData[NonceSize+PlaintextSize : SessionIDSize]

	// Verify MAC first (before decryption)
	expectedMAC := computeMAC(authKey, nonce, ciphertext)
	if subtle.ConstantTimeCompare(expectedMAC[:MACSize], receivedMAC) != 1 {
		return nil, ErrDecryptionFailed
	}

	// Decrypt
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}

	ctrIV := make([]byte, aes.BlockSize)
	copy(ctrIV, nonce)
	stream := cipher.NewCTR(block, ctrIV)

	plaintext := make([]byte, PlaintextSize)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// computeMAC computes HMAC-SHA256 over the given data, returning the full hash.
func computeMAC(key, nonce, ciphertext []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(nonce)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// PublicKeyFromPrivate derives the public key from a private key.
func PublicKeyFromPrivate(private [KeySize]byte) ([KeySize]byte, error) {
	var public [KeySize]byte
	publicSlice, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return public, err
	}
	copy(public[:], publicSlice)
	return public, nil
}
