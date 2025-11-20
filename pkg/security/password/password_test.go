/*
Package password contains Argon2 utilities.
*/
package password

import (
	"testing"

	"github.com/matthewhartstonge/argon2"
	"github.com/stretchr/testify/require"
)

func TestPassword(t *testing.T) {
	t.Run("Password", func(t *testing.T) {
		t.Parallel()
		s := "my-password"
		encoded, err := Encode(s, argon2.DefaultConfig())
		require.NoError(t, err, "encode password")
		match, err := Verify(s, encoded)
		require.NoError(t, err, "verify password")
		require.True(t, match, "match password")
		match, err = Verify("not", encoded)
		require.NoError(t, err, "verify password")
		require.False(t, match, "match password")
	})
}
