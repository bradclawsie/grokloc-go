/*
Package crypt contains crytographic utilities.
*/
package crypt

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCrypt(t *testing.T) {
	t.Run("Encrypt", func(t *testing.T) {
		t.Parallel()
		key := RandomKey()
		s := uuid.NewString()
		e, err := Encrypt(s, key)
		require.NoError(t, err, "encrypt fail")
		digestBytes := sha256.Sum256([]byte(s))
		d, err := Decrypt(e, hex.EncodeToString(digestBytes[:]), key)
		require.NoError(t, err, "decrypt fail")
		require.Equal(t, s, d, "cannot round trip encrypted value")

		_, err = Decrypt(e, hex.EncodeToString(digestBytes[:]), RandomKey())
		require.Error(t, err, "should fail on different key")
	})
}
