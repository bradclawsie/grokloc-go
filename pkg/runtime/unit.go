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

func unit() (*State, error) {
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

	signingKey := key.Random()

	// Version key map.
	keyMap := make(key.VersionMap)
	// `current` is the key in use now.
	current := uuid.New()
	keyMap[current] = key.Random()
	// Previous keys, still permitted.
	keyMap[uuid.New()] = key.Random()
	keyMap[uuid.New()] = key.Random()

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

		Argon2Config:  argon2Config,
		SigningKey:    signingKey,
		EncryptionKey: keyMap[current],
		KeyMap:        keyMap,
	}
	return st, nil
}
