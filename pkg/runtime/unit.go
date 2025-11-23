/*
Package runtime provides types and utilties for
communicating with the execution environment.
*/
package runtime

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
	"grokloc.com/pkg/model/role"
	"grokloc.com/pkg/security/key"
)

func Unit() (*State, error) {
	logger := slog.New(slog.NewJSONHandler(
		os.Stderr,
		&slog.HandlerOptions{AddSource: true, Level: slog.LevelError},
	))

	dbUrl, dbUrlOK := os.LookupEnv(PostgresAppUrlEnvKey)
	if !dbUrlOK {
		return nil, ErrEnvVar
	}

	_, dbUrlParseErr := pgconn.ParseConfig(dbUrl)
	if dbUrlParseErr != nil {
		return nil, ErrEnvVar
	}

	ctx := context.Background()

	master, poolErr := pgxpool.New(ctx, dbUrl)
	if poolErr != nil {
		return nil, poolErr
	}

	replicas := make([]*pgxpool.Pool, 1)
	replicas[0] = master

	argon2Config := argon2.DefaultConfig()
	argon2Config.TimeCost = 1

	repositoryBase, repositoryBaseOK := os.LookupEnv(RepositoryBaseEnvKey)
	if !repositoryBaseOK {
		return nil, ErrEnvVar
	}
	_, repositoryBaseErr := os.Stat(repositoryBase)
	if repositoryBaseErr != nil {
		return nil, repositoryBaseErr
	}

	currentEncryptionKey := key.Versioned{
		Version: uuid.New(),
		Key:     key.Random(),
	}
	encryptionKeys := make(key.VersionedMap)
	encryptionKeys[currentEncryptionKey.Version] = currentEncryptionKey.Key
	encryptionKeys[uuid.New()] = key.Random()
	encryptionKeys[uuid.New()] = key.Random()

	st := &State{
		Logger: logger,

		Level:      "unit",
		ApiVersion: 0,

		Master:      master,
		Replicas:    replicas,
		ConnTimeout: time.Duration(1000 * time.Millisecond),
		ExecTimeout: time.Duration(1000 * time.Millisecond),
		DefaultRole: role.Test,

		RepositoryBase: repositoryBase,

		Argon2Config: argon2Config,
		SigningKey:   key.Random(),

		EncryptionKeyVersion: currentEncryptionKey.Version,
		EncryptionKeys:       encryptionKeys,
	}
	return st, nil
}
