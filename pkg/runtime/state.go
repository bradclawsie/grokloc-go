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

	"github.com/google/uuid"
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

	// EncryptionKeyVersion is the version of the current encryption key.
	EncryptionKeyVersion uuid.UUID

	// EncryptionKeys is a map of version -> key for all keys
	// available for use, including keys no longer in rotation.
	EncryptionKeys key.VersionedMap
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
		return Unit()
	}
	panic("environment not supported")
}

// Close can be run when a `State` instance is no longer needed.
func (s *State) Close() error {
	if s.Master != nil {
		s.Master.Close()
	}
	for i := range s.Replicas {
		s.Replicas[i].Close()
	}
	return nil
}
