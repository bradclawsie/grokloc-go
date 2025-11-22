/*
Package jwt provides conveniences for dealing with JWTs as
GrokLOC specifies.
*/
package jwt

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"grokloc.com/pkg/security/key"
)

func TestJWT(t *testing.T) {
	t.Run("EncodeDecode", func(t *testing.T) {
		t.Parallel()
		sub, err := uuid.NewRandom()
		require.NoError(t, err, "random")
		signingKey := key.Random()
		tokenStr, err := Encode(sub, signingKey)
		require.NoError(t, err, "Encode")
		token, err := Decode(tokenStr, signingKey)
		require.NoError(t, err, "Decode")
		claimsSub, err := token.Claims.GetSubject()
		require.NoError(t, err, "GetSubject")
		require.Equal(t, claimsSub, sub.String())

		_, err = Decode(tokenStr, key.Random())
		require.Error(t, err, "bad signing key")
	})
}
