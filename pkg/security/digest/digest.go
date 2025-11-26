/*
Package digest provides digest encoding utilities.
*/
package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the hex-encoded sha256 digest of `s`.
func SHA256Hex(s string) string {
	hasher := sha256.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}
