/*
Package versionkey is just a glorified map of key versions
(expressed as UUIDs), to keys.
*/
package versionkey

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"grokloc.com/pkg/security/crypt"
)

func TestVersionKey(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		id0 := uuid.New()
		k0 := crypt.RandomKey()
		id1 := uuid.New()
		k1 := crypt.RandomKey()
		keyMap := map[uuid.UUID][]byte{
			id0: k0,
			id1: k1,
		}
		v, newErr := New(KeyMap(keyMap), id0)
		require.NoError(t, newErr)
		kGet, getErr := v.Get(id1)
		require.NoError(t, getErr, "get id1")
		require.Equal(t, k1, kGet, "id1 key")
		versionCurrent, kCurrent, currentErr := v.GetCurrent()
		require.NoError(t, currentErr, "get current")
		require.Equal(t, id0, versionCurrent, "current version")
		require.Equal(t, k0, kCurrent, "current key")

	})
}
