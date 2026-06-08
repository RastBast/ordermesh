package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	kr, err := NewKeyring([][]byte{mustKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("alice@example.com")
	aad := []byte("order-123")

	enc, err := kr.Encrypt(plain, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := kr.Decrypt(enc, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %s", got)
	}
}

func TestAADMismatchFails(t *testing.T) {
	t.Parallel()
	kr, _ := NewKeyring([][]byte{mustKey(t)})
	enc, _ := kr.Encrypt([]byte("secret"), []byte("order-1"))
	if _, err := kr.Decrypt(enc, []byte("order-2")); err == nil {
		t.Fatal("expected auth failure on AAD mismatch")
	}
}

func TestKeyRotation(t *testing.T) {
	t.Parallel()
	k1 := mustKey(t)
	k2 := mustKey(t)

	// Encrypt with only k1 active.
	old, _ := NewKeyring([][]byte{k1})
	enc, _ := old.Encrypt([]byte("legacy"), nil)

	// After rotation, k2 is active but k1 still decrypts old data.
	rotated, _ := NewKeyring([][]byte{k1, k2})
	got, err := rotated.Decrypt(enc, nil)
	if err != nil {
		t.Fatalf("decrypt legacy after rotation: %v", err)
	}
	if string(got) != "legacy" {
		t.Fatalf("want legacy, got %s", got)
	}

	// New ciphertexts use k2 (index 1).
	enc2, _ := rotated.EncryptString("fresh", "")
	if enc2 == "" {
		t.Fatal("empty ciphertext")
	}
	dec2, _ := rotated.DecryptString(enc2, "")
	if dec2 != "fresh" {
		t.Fatalf("want fresh, got %s", dec2)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := NewKeyring([][]byte{make([]byte, 16)}); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestTamperDetection(t *testing.T) {
	t.Parallel()
	kr, _ := NewKeyring([][]byte{mustKey(t)})
	enc, _ := kr.EncryptString("data", "aad")
	// flip a character in the middle of the ciphertext body
	b := []byte(enc)
	mid := len(b) / 2
	if b[mid] == 'A' {
		b[mid] = 'B'
	} else {
		b[mid] = 'A'
	}
	tampered := string(b)
	if _, err := kr.DecryptString(tampered, "aad"); err == nil {
		t.Fatal("expected failure on tampered ciphertext")
	}
}
