/*
Package key defines the database encryption key and provides
supporting utilties.
*/
package key

import (
	"crypto/rand"
	"io"

	"github.com/google/uuid"
)

// AESGCM key length.
const Length = 32

// Random returns a new random key.
func Random() []byte {
	bs := make([]byte, Length)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		panic(err)
	}
	return bs
}

// VersionMap is the data structure used to hold key ids
// (as UUIDs) -> key []byte.
type VersionMap map[uuid.UUID][]byte
