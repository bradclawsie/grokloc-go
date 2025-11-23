/*
Package password contains Argon2 utilities.
*/
package password

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/matthewhartstonge/argon2"
)

// Encode performs a one-way hash on a password using argon2.
func Encode(password string, cfg argon2.Config) (string, error) {
	raw, err := cfg.Hash([]byte(password), nil)
	if err != nil {
		return "", err
	}
	return string(raw.Encode()), err
}

// Verify returns true if guess is the same as encoded.
func Verify(guess string, encoded string) (bool, error) {
	return argon2.VerifyEncoded([]byte(guess), []byte(encoded))
}

// Random generates a new random password. Mostly for testing.
func Random() string {
	password, err := Encode(uuid.NewString(), argon2.DefaultConfig())
	if err != nil {
		panic(fmt.Sprintf("random password:%v", err))
	}
	return password
}
