/*
Package org provides utilities to create, read, and update
rows in the `orgs` database table.
*/
package org

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"grokloc.com/pkg/model/role"
	"grokloc.com/pkg/model/status"
	"grokloc.com/pkg/postgresql"
	"grokloc.com/pkg/runtime"
	"grokloc.com/pkg/security/password"
)

var st *runtime.State

func TestMain(m *testing.M) {
	var stErr error
	st, stErr = runtime.Unit()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}
	m.Run()
}

func TestInsert(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		ownerEd25519Public, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err, "generate ed25519")
		require.NotEqual(t, "", ownerEd25519Public, "rm")

		name := uuid.NewString()
		ownerVersionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")
		ownerDisplayName := uuid.NewString()
		ownerEmail := uuid.NewString()
		ownerPassword := password.Random()

		before := time.Now().Unix()
		org, owner, err := Insert(
			context.Background(),
			conn.Conn(),
			name,
			*ownerVersionKey,
			ownerDisplayName,
			hex.EncodeToString(ownerEd25519Public),
			ownerEmail,
			ownerPassword,
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.NoError(t, err, "insert")
		require.NotNil(t, owner.ID, "owner ID")
		require.Equal(t, org.ID, owner.Org, "owner org")
		require.Equal(t, role.Test, owner.Role, "owner role")
		require.Equal(t,
			SchemaVersion,
			owner.SchemaVersion,
			"owner schema version")
		require.Equal(t, status.Active,
			owner.Status,
			"owner status")
		require.Equal(t, name, org.Name, "name")
		require.Equal(t, owner.ID, org.Owner, "owner")
		require.True(t, before <= org.Ctime, "ctime")
		require.True(t, before <= org.Mtime, "mtime")
		require.True(t, org.InsertOrder > 0, "insert order")
		require.Equal(t, org.Ctime, org.Mtime, "time")
		require.Equal(t, role.Test, org.Role, "role")
	})

	t.Run("Conflict", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		ownerEd25519Public, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err, "generate ed25519")
		require.NotEqual(t, "", ownerEd25519Public, "rm")

		name := uuid.NewString()
		ownerVersionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		_, _, err = Insert(
			context.Background(),
			conn.Conn(),
			name,
			*ownerVersionKey,
			uuid.NewString(),
			hex.EncodeToString(ownerEd25519Public),
			uuid.NewString(),
			uuid.NewString(),
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.NoError(t, err, "insert")

		_, _, err = Insert(
			context.Background(),
			conn.Conn(),
			name,
			*ownerVersionKey,
			uuid.NewString(),
			hex.EncodeToString(ownerEd25519Public),
			uuid.NewString(),
			uuid.NewString(),
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.Error(t, err, "name conflict")
		require.True(t, postgresql.UniqueConstraint(err), "err")
	})
}

func TestRead(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		ownerVersionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")
		org, _ := ForTest(
			context.Background(),
			conn.Conn(),
			*ownerVersionKey,
			status.Active,
		)

		readOrg, err := Read(
			context.Background(),
			conn.Conn(),
			org.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *org, *readOrg, "round trip")
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		conn, err := st.RandomReplica().Acquire(context.Background())
		require.NoError(t, err, "replica conn")
		defer conn.Release()

		_, err = Read(
			context.Background(),
			conn.Conn(),
			uuid.New(),
		)

		require.Error(t, err, "read")
		require.Equal(t, err, pgx.ErrNoRows, "not found")
	})
}

func TestUpdateStatus(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		ownerVersionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		org, _ := ForTest(
			context.Background(),
			conn.Conn(),
			*ownerVersionKey,
			status.Active,
		)

		mtime := org.Mtime
		signature := org.Signature
		require.Equal(t, status.Active, org.Status)

		err = org.UpdateStatus(
			context.Background(),
			conn.Conn(),
			status.Inactive,
		)

		require.NoError(t, err, "update status")
		require.Equal(t, status.Inactive, org.Status, "status")
		require.True(t, mtime <= org.Mtime, "mtime")
		require.NotEqual(t, signature, org.Signature, "signature")

		readOrg, err := Read(
			context.Background(),
			conn.Conn(),
			org.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *org, *readOrg, "round trip")
	})

	t.Run("BadStatus", func(t *testing.T) {
		t.Parallel()
		conn, err := st.RandomReplica().Acquire(context.Background())
		require.NoError(t, err, "replica conn")
		defer conn.Release()

		ownerVersionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		org, _ := ForTest(
			context.Background(),
			conn.Conn(),
			*ownerVersionKey,
			status.Active,
		)

		status := org.Status
		err = org.UpdateStatus(
			context.Background(),
			conn.Conn(),
			99,
		)

		require.Error(t, err, "update status")
		require.Equal(t, status, org.Status, "status unchanged")
	})
}
