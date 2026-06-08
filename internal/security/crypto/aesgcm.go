// Package crypto provides authenticated, application-level encryption for PII
// stored at rest (defence-in-depth on top of disk/volume encryption).
//
// It implements an envelope-style AES-256-GCM scheme with key versioning so
// keys can be rotated without re-encrypting historic data: the ciphertext is
// prefixed with the key id used to produce it.
//
//	stored value = base64( keyID(1 byte index) || nonce(12) || ciphertext+tag )
//
// Keys are 32-byte (AES-256) values supplied from a secret manager (Vault /
// KMS / External Secrets). The newest key is used for encryption; any known
// key can be used for decryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	keyLen   = 32 // AES-256
	nonceLen = 12 // GCM standard nonce
)

var (
	// ErrNoKeys is returned when the keyring has no keys.
	ErrNoKeys = errors.New("crypto: empty keyring")
	// ErrUnknownKey is returned when a ciphertext references an unknown key id.
	ErrUnknownKey = errors.New("crypto: unknown key id")
	// ErrCiphertextTooShort indicates malformed input.
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")
	// ErrInvalidKeyLength indicates a key that is not 32 bytes.
	ErrInvalidKeyLength = errors.New("crypto: key must be 32 bytes")
)

// Keyring holds versioned AEAD ciphers. Index 0..n; the highest index is the
// active encryption key. This makes rotation a config change, not a migration.
type Keyring struct {
	aeads     []cipher.AEAD
	activeIdx byte
}

// NewKeyring builds a keyring from raw 32-byte keys, ordered oldest→newest.
func NewKeyring(keys [][]byte) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if len(keys) > 256 {
		return nil, errors.New("crypto: too many keys (max 256)")
	}
	aeads := make([]cipher.AEAD, 0, len(keys))
	for i, k := range keys {
		if len(k) != keyLen {
			return nil, fmt.Errorf("%w (key #%d)", ErrInvalidKeyLength, i)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("new cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("new gcm: %w", err)
		}
		aeads = append(aeads, aead)
	}
	return &Keyring{aeads: aeads, activeIdx: byte(len(aeads) - 1)}, nil
}

// Encrypt seals plaintext with the active key. The associated data (aad) is
// authenticated but not encrypted — pass a stable context (e.g. order id) to
// bind ciphertexts to their record and prevent copy-paste attacks.
func (k *Keyring) Encrypt(plaintext, aad []byte) (string, error) {
	if len(k.aeads) == 0 {
		return "", ErrNoKeys
	}
	aead := k.aeads[k.activeIdx]

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, 1+nonceLen+len(sealed))
	out = append(out, k.activeIdx)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a value produced by Encrypt, selecting the key by its embedded id.
func (k *Keyring) Decrypt(encoded string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 1+nonceLen+16 { // 16 = GCM tag
		return nil, ErrCiphertextTooShort
	}
	idx := raw[0]
	if int(idx) >= len(k.aeads) {
		return nil, ErrUnknownKey
	}
	nonce := raw[1 : 1+nonceLen]
	ciphertext := raw[1+nonceLen:]

	plaintext, err := k.aeads[idx].Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}

// EncryptString is a convenience wrapper for string PII.
func (k *Keyring) EncryptString(plaintext, aad string) (string, error) {
	return k.Encrypt([]byte(plaintext), []byte(aad))
}

// DecryptString is a convenience wrapper returning a string.
func (k *Keyring) DecryptString(encoded, aad string) (string, error) {
	b, err := k.Decrypt(encoded, []byte(aad))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ConstantTimeEqual compares two secrets without leaking timing information.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
