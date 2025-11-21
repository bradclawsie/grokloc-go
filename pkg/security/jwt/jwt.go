/*
Package jwt provides conveniences for dealing with JWTs as
GrokLOC specifies.
*/
package jwt

import (
	"errors"
	"time"

	go_jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	Expiration        = 86400
	AuthorizationType = "Bearer"
)

var ErrIncorrectSigningMethod = errors.New("signing method not HS256")

// Encode produces a signed JWT.
func Encode(sub uuid.UUID, signingKey []byte) (string, error) {
	now := time.Now().Unix()
	tok := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, go_jwt.MapClaims{
		"iss": "GrokLOC.com",
		"sub": sub.String(),
		"nbf": now,
		"iat": now,
		"exp": now + Expiration,
	})
	return tok.SignedString(signingKey)
}

// Decode takes the string returned by `Encode` and decodes the token.
func Decode(tokenStr string, signingKey []byte) (*go_jwt.Token, error) {
	return go_jwt.Parse(tokenStr, func(token *go_jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*go_jwt.SigningMethodHMAC); !ok {
			return nil, ErrIncorrectSigningMethod
		}
		return signingKey, nil
	})
}
