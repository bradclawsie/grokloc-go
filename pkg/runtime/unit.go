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
	"grokloc.com/pkg/security/crypt"
	"grokloc.com/pkg/security/versionkey"
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

	signingKey := crypt.RandomKey()

	// Version key map.
	// KnownKeyID will be set as a key version, not current.
	// This value was chosen randomly.
	const KnownKeyID = "c4d98d26-e6d4-4e75-b88b-dfbe8361757a"
	keyMap := make(versionkey.KeyMap)
	current := uuid.New()
	keyMap[current] = crypt.RandomKey()
	keyMap[uuid.New()] = crypt.RandomKey()
	keyMap[uuid.MustParse(KnownKeyID)] = crypt.RandomKey()

	versionKey, vkErr := versionkey.New(keyMap, current)
	if vkErr != nil {

		return nil, vkErr
	}

	return &State{
		Level:          "unit",
		Logger:         logger,
		ApiVersion:     0,
		Master:         master,
		Replicas:       replicas,
		ConnTimeout:    time.Duration(1000 * time.Millisecond),
		ExecTimeout:    time.Duration(1000 * time.Millisecond),
		Argon2Config:   argon2Config,
		RepositoryBase: repositoryBase,
		SigningKey:     signingKey,
		VersionKey:     versionKey,
		DefaultRole:    role.Test,
	}, nil
}
