/*
Package key defines the database encryption key and provides
supporting utilties.
*/
package key

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/google/uuid"
)

const (
	Length = 32
)

var (
	ErrNotFound = errors.New("key version not found")
)

// Random returns a new random key.
func Random() []byte {
	bs := make([]byte, Length)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		panic(err)
	}
	return bs
}

// Versioned identifies a key with a uuid version.
type Versioned struct {
	Version uuid.UUID
	Key     []byte
}

// VersionedMap contains all versioned keys available.
type VersionedMap map[uuid.UUID][]byte

// Get returns the `Versioned` instance for a key.
func (v VersionedMap) Get(u uuid.UUID) (*Versioned, error) {
	key, ok := v[u]
	if !ok {
		return nil, ErrNotFound
	}

	return &Versioned{
		Version: u,
		Key:     key,
	}, nil
}
