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
	"grokloc.com/pkg/security/key"
)

func TestCrypt(t *testing.T) {
	t.Run("Encrypt", func(t *testing.T) {
		t.Parallel()
		k := key.Random()
		s := uuid.NewString()
		e, err := Encrypt(s, k)
		require.NoError(t, err, "encrypt fail")
		digestBytes := sha256.Sum256([]byte(s))
		d, err := Decrypt(e, hex.EncodeToString(digestBytes[:]), k)
		require.NoError(t, err, "decrypt fail")
		require.Equal(t, s, d, "round trip")

		// Bad key.
		_, err = Decrypt(e, hex.EncodeToString(digestBytes[:]), key.Random())
		require.Error(t, err, "bad key")

		// Bad digest.
		_, err = Decrypt(e, "abcd", k)
		require.Error(t, err, "bad digest")
		require.Equal(t, ErrDigest, err, "digest err")
	})
}
