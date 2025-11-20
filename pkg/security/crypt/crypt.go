/*
Package crypt contains crytographic utilities.
*/
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// KeyLength for AESGCM.
const KeyLength = 32

var (
	ErrDigest = errors.New("value does not have correct digest")
	ErrNonce  = errors.New("nonce could not be constructed")
)

// RandomKey returns a new random key.
func RandomKey() []byte {
	bs := make([]byte, KeyLength)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		panic(err)
	}
	return bs
}

// Encrypt returns the hex-encoded AES symmetric encryption
// of s with key.
func Encrypt(s string, key []byte) (string, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(s), nil)), nil
}

// Decrypt reverses the value e produced by Encrypt. Decrypted value
// must have a sha256 that matches expectedDigest.
func Decrypt(e, expectedDigest string, key []byte) (string, error) {
	d, err := hex.DecodeString(e)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(d) < nonceSize {
		return "", ErrNonce
	}
	nonce, msg := d[:nonceSize], d[nonceSize:]
	bs, err := gcm.Open(nil, nonce, msg, nil) // #nosec G407
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bs)
	if hex.EncodeToString(sum[:]) != expectedDigest {
		return "", ErrDigest
	}
	return string(bs), nil
}
