/*
Package runtime provides types and utilties for
communicating with the execution environment.
*/
package runtime

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
	"grokloc.com/pkg/security/key"
)

const (
	LevelEnvKey          = "LEVEL"
	PostgresAppUrlEnvKey = "POSTGRES_APP_URL"
	RepositoryBaseEnvKey = "REPOSITORY_BASE"
)

var ErrEnvVar = errors.New("environment variable not found or malformed")

// State contains all environment-specific runtime definitions.
type State struct {
	Logger *slog.Logger

	// Versioning
	Level      string
	ApiVersion int

	// Database related.
	Master      *pgxpool.Pool
	Replicas    []*pgxpool.Pool
	ConnTimeout time.Duration
	ExecTimeout time.Duration
	DefaultRole int

	// Repository related.
	RepositoryBase string

	// Crypt related.

	// Password hash config.
	Argon2Config argon2.Config

	// SigningKey signs JWTs.
	SigningKey []byte

	// EncryptionKey is the current database key in use.
	EncryptionKey key.Versioned

	// ExpiredEncryptionKeys is a list of previously
	// used keys. Should be no more than two keys.
	// Allows decryption of older records prior to, or during
	// key rotation.
	ExpiredEncryptionKeys []key.Versioned
}

// RandomReplica selects a random replica.
func (s *State) RandomReplica() *pgxpool.Pool {
	l := len(s.Replicas)
	if l == 0 {
		panic("no replicas")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(l)))
	if err != nil {
		panic(fmt.Sprintf("random replica index in 0:%v", l))
	}
	return s.Replicas[n.Int64()]
}

// New produces a new `State` instance for the level set in
// environment variable `LEVEL`.
func New() (*State, error) {
	level, levelOK := os.LookupEnv(LevelEnvKey)
	if !levelOK {
		return nil, ErrEnvVar
	}
	if level == "unit" {
		return unit()
	}
	panic("environment not supported")
}
