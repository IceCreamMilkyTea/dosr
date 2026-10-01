package notary

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// GenerateKey creates a fresh notary signing key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("notary: generating key: %w", err)
	}
	return priv, nil
}

// LoadKey reads a notary key file: the 32-byte ed25519 seed in hex,
// optionally followed by a newline. The file must not be accessible by
// group or others (mode 0600 or stricter); a key file with wider
// permissions is refused, like OpenSSH does.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("notary: opening key file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("notary: key file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("notary: key file is not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("notary: key file %s has mode %04o; it must not be accessible by group or others (chmod 600)", path, st.Mode().Perm())
	}
	if st.Size() > 256 {
		return nil, errors.New("notary: key file is too large")
	}
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	seed, err := hex.DecodeString(string(bytes.TrimSpace(buf[:n])))
	if err != nil || len(seed) != ed25519.SeedSize {
		// Do not include the content in the error.
		return nil, errors.New("notary: key file does not contain a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SaveKey writes key to a NEW file with mode 0600. It fails if the file
// exists (a key is never overwritten).
func SaveKey(path string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("notary: bad key length")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("notary: creating key file: %w", err)
	}
	_, werr := f.WriteString(hex.EncodeToString(key.Seed()) + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return fmt.Errorf("notary: writing key file: %w", werr)
	}
	return nil
}

// LoadOrCreateKey loads the key at path, or generates one and saves it
// there (mode 0600) if the file does not exist. created reports which.
func LoadOrCreateKey(path string) (key ed25519.PrivateKey, created bool, err error) {
	key, err = LoadKey(path)
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if key, err = GenerateKey(); err != nil {
		return nil, false, err
	}
	if err = SaveKey(path, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}
