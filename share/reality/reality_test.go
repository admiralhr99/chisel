package reality

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Verify keys are not zero
	var zeroKey [KeySize]byte
	if priv == zeroKey {
		t.Error("private key is zero")
	}
	if pub == zeroKey {
		t.Error("public key is zero")
	}

	// Verify public key can be derived from private
	derivedPub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate failed: %v", err)
	}
	if derivedPub != pub {
		t.Error("derived public key doesn't match")
	}
}

func TestCreateAndVerifySessionID(t *testing.T) {
	// Generate server keypair
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	shortID := []byte("testid")

	// Create session ID (client side)
	sessionID, clientPub, err := CreateSessionID(serverPub, shortID)
	if err != nil {
		t.Fatalf("CreateSessionID failed: %v", err)
	}

	// Verify session ID (server side)
	err = VerifySessionID(sessionID, clientPub, serverPriv, shortID)
	if err != nil {
		t.Fatalf("VerifySessionID failed: %v", err)
	}
}

func TestVerifySessionID_WrongShortID(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create with one short ID
	sessionID, clientPub, err := CreateSessionID(serverPub, []byte("correct"))
	if err != nil {
		t.Fatalf("CreateSessionID failed: %v", err)
	}

	// Verify with different short ID
	err = VerifySessionID(sessionID, clientPub, serverPriv, []byte("wrong"))
	if err != ErrShortIDMismatch {
		t.Errorf("expected ErrShortIDMismatch, got: %v", err)
	}
}

func TestVerifySessionID_WrongServerKey(t *testing.T) {
	_, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create session with correct server public key
	sessionID, clientPub, err := CreateSessionID(serverPub, []byte("test"))
	if err != nil {
		t.Fatalf("CreateSessionID failed: %v", err)
	}

	// Try to verify with different server private key
	wrongPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	err = VerifySessionID(sessionID, clientPub, wrongPriv, []byte("test"))
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestVerifySessionID_EmptyShortID(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create and verify with empty short ID
	sessionID, clientPub, err := CreateSessionID(serverPub, nil)
	if err != nil {
		t.Fatalf("CreateSessionID failed: %v", err)
	}

	err = VerifySessionID(sessionID, clientPub, serverPriv, nil)
	if err != nil {
		t.Fatalf("VerifySessionID failed: %v", err)
	}
}

func TestSessionIDSize(t *testing.T) {
	_, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	sessionID, _, err := CreateSessionID(serverPub, []byte("test"))
	if err != nil {
		t.Fatalf("CreateSessionID failed: %v", err)
	}

	if len(sessionID) != SessionIDSize {
		t.Errorf("session ID size: got %d, want %d", len(sessionID), SessionIDSize)
	}
}

func BenchmarkCreateSessionID(b *testing.B) {
	_, serverPub, _ := GenerateKeyPair()
	shortID := []byte("bench")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreateSessionID(serverPub, shortID)
	}
}

func BenchmarkVerifySessionID(b *testing.B) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID := []byte("bench")
	sessionID, clientPub, _ := CreateSessionID(serverPub, shortID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySessionID(sessionID, clientPub, serverPriv, shortID)
	}
}
