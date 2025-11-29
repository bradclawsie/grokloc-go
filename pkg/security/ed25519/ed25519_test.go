/*
Package ed25519 provides convenient generation and encoding
for Ed25519 keys.
*/
package ed25519

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		ed25519PublicPEM, ed25519PrivatePEM, err := Random()
		require.NoError(t, err, "random")
		_, err = ImportPublicPEM(ed25519PublicPEM)
		require.NoError(t, err, "public pem")
		_, err = ImportPrivatePEM(ed25519PrivatePEM)
		require.NoError(t, err, "private pem")
	})
}
