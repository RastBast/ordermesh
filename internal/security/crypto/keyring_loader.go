package crypto

import (
	"encoding/base64"
	"fmt"
)

// LoadKeyring decodes base64-encoded 32-byte keys (oldest→newest) into a
// Keyring. Intended to be fed from a secret manager via configuration.
func LoadKeyring(b64keys []string) (*Keyring, error) {
	if len(b64keys) == 0 {
		return nil, ErrNoKeys
	}
	keys := make([][]byte, 0, len(b64keys))
	for i, s := range b64keys {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Also accept raw-url encoding for convenience.
			raw, err = base64.RawURLEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("decode key #%d: %w", i, err)
			}
		}
		keys = append(keys, raw)
	}
	return NewKeyring(keys)
}
