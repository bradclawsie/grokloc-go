/*
Package user provides utilities to create, read, and update
rows in the `users` database table.
*/
package user

import (
	"context"
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
	"grokloc.com/pkg/security/digest"
	"grokloc.com/pkg/security/ed25519"
	"grokloc.com/pkg/security/key"
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

		ed25519PublicPEM, _, err := ed25519.Random()
		require.NoError(t, err, "generate ed25519")

		displayName := uuid.NewString()
		email := uuid.NewString()
		org := uuid.New()
		password := password.Random()
		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		before := time.Now().Unix()
		user, err := Insert(
			context.Background(),
			conn.Conn(),
			*versionKey,
			displayName,
			ed25519PublicPEM,
			email,
			org,
			password,
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.NoError(t, err, "insert")
		require.NotNil(t, user.ID, "ID")
		require.Equal(t, displayName, user.DisplayName, "display name")
		require.Equal(t, digest.SHA256Hex(displayName),
			user.DisplayNameDigest, "display name digest")
		require.Equal(t, ed25519PublicPEM,
			user.Ed25519Public, "ed25519Public")
		require.Equal(t,
			digest.SHA256Hex(ed25519PublicPEM),
			user.Ed25519PublicDigest, "ed25519Public digest")
		require.Equal(t, email, user.Email, "email")
		require.Equal(t, digest.SHA256Hex(email),
			user.EmailDigest, "email digest")
		require.Equal(t, st.EncryptionKeyVersion,
			user.KeyVersion, "key version")
		require.Equal(t, org, user.Org, "org")
		require.Equal(t, password, user.Password, "password")
		require.True(t, before <= user.Ctime, "ctime")
		require.True(t, before <= user.Mtime, "mtime")
		require.True(t, user.InsertOrder > 0, "insert order")
		require.Equal(t, user.Ctime, user.Mtime, "time")
		require.Equal(t, role.Test, user.Role, "role")
		require.Equal(t, SchemaVersion,
			user.SchemaVersion, "schema version")
		require.NotNil(t, user.Signature, "signature")
		require.Equal(t, status.Active, user.Status, "status")
	})

	t.Run("Conflict", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		ed25519PublicPEM, _, err := ed25519.Random()
		require.NoError(t, err, "generate ed25519")
		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user, err := Insert(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.NewString(), // display name
			ed25519PublicPEM,
			uuid.NewString(),  // email
			uuid.New(),        // org
			password.Random(), // password
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.NoError(t, err, "insert")

		// Conflict when ed25519Public is used twice in user.Org.
		_, err = Insert(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.NewString(), // display name
			ed25519PublicPEM,
			uuid.NewString(), // email
			user.Org,
			password.Random(), // password
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.Error(t, err, "ed25519 conflict")
		require.True(t, postgresql.UniqueConstraint(err), "err")

		// Conflict when email is used twice in user.Org.

		// Get a new ed25519Pub so that conflict won't trigger.
		ed25519PublicPEM, _, err = ed25519.Random()
		require.NoError(t, err, "generate ed25519")

		_, err = Insert(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.NewString(), // display name
			ed25519PublicPEM,
			user.Email,
			user.Org,
			password.Random(), // password
			role.Test,
			SchemaVersion,
			status.Active,
		)

		require.Error(t, err, "email conflict")
		require.True(t, postgresql.UniqueConstraint(err), "err")
	})
}

func TestRead(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)
		readUser, err := Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			user.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *user, *readUser, "round trip")
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		conn, err := st.RandomReplica().Acquire(context.Background())
		require.NoError(t, err, "replica conn")
		defer conn.Release()

		_, err = Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			uuid.New(),
		)

		require.Error(t, err, "read")
		require.Equal(t, err, pgx.ErrNoRows, "not found")
	})

	t.Run("Key", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		// Empty VersionedMap does not have user.KeyVersion.
		_, err = Read(
			context.Background(),
			conn.Conn(),
			make(key.VersionedMap),
			user.ID,
		)

		require.Error(t, err, "read")
		require.Equal(t, key.ErrNotFound, err, "not found err")
	})

}

func TestNewEd25519(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		mtime := user.Mtime
		signature := user.Signature
		require.Equal(t, status.Active, user.Status)

		ed25519PublicPEM, _, err := ed25519.Random()
		require.NoError(t, err, "generate ed25519")

		err = user.NewEd25519(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			ed25519PublicPEM,
		)

		require.NoError(t, err, "new ed25519")
		require.Equal(t, ed25519PublicPEM,
			user.Ed25519Public, "ed25519_public")
		require.True(t, mtime <= user.Mtime, "mtime")
		require.NotEqual(t, signature, user.Signature, "signature")

		readUser, err := Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			user.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *user, *readUser, "round trip")
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		ed25519PublicPEM, _, err := ed25519.Random()
		require.NoError(t, err, "generate ed25519")

		// Decryption key will not be found in empty map.
		emptyEncryptionKeys := make(key.VersionedMap)

		err = user.NewEd25519(
			context.Background(),
			conn.Conn(),
			emptyEncryptionKeys,
			ed25519PublicPEM,
		)

		require.Error(t, err, "empty keys")
		require.Equal(t, err, key.ErrNotFound, "not found")
	})
}

func TestUpdateDisplayName(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		mtime := user.Mtime
		signature := user.Signature
		require.Equal(t, status.Active, user.Status)

		displayName := uuid.NewString()

		err = user.UpdateDisplayName(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			displayName,
		)

		require.NoError(t, err, "update display name")
		require.Equal(t, displayName,
			user.DisplayName, "displayName")
		require.True(t, mtime <= user.Mtime, "mtime")
		require.NotEqual(t, signature, user.Signature, "signature")

		readUser, err := Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			user.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *user, *readUser, "round trip")
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		// Decryption key will not be found in empty map.
		emptyEncryptionKeys := make(key.VersionedMap)

		err = user.UpdateDisplayName(
			context.Background(),
			conn.Conn(),
			emptyEncryptionKeys,
			uuid.NewString(),
		)

		require.Error(t, err, "empty keys")
		require.Equal(t, err, key.ErrNotFound, "not found")
	})
}

func TestUpdatePassword(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		mtime := user.Mtime
		signature := user.Signature
		require.Equal(t, status.Active, user.Status)

		pw := password.Random()

		err = user.UpdatePassword(
			context.Background(),
			conn.Conn(),
			pw,
		)

		require.NoError(t, err, "update password")
		require.Equal(t, pw, user.Password, "password")
		require.True(t, mtime <= user.Mtime, "mtime")
		require.NotEqual(t, signature, user.Signature, "signature")

		readUser, err := Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			user.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *user, *readUser, "round trip")
	})
}

func TestUpdateStatus(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		mtime := user.Mtime
		signature := user.Signature
		require.Equal(t, status.Active, user.Status)

		err = user.UpdateStatus(
			context.Background(),
			conn.Conn(),
			status.Inactive,
		)

		require.NoError(t, err, "update status")
		require.Equal(t, status.Inactive, user.Status, "status")
		require.True(t, mtime <= user.Mtime, "mtime")
		require.NotEqual(t, signature, user.Signature, "signature")

		readUser, err := Read(
			context.Background(),
			conn.Conn(),
			st.EncryptionKeys,
			user.ID,
		)

		require.NoError(t, err, "read")
		require.Equal(t, *user, *readUser, "round trip")
	})

	t.Run("BadStatus", func(t *testing.T) {
		t.Parallel()
		conn, err := st.Master.Acquire(context.Background())
		require.NoError(t, err, "master conn")
		defer conn.Release()

		versionKey, err := st.EncryptionKeys.Get(st.EncryptionKeyVersion)
		require.NoError(t, err, "versionKey")

		user := ForTest(
			context.Background(),
			conn.Conn(),
			*versionKey,
			uuid.New(),
			status.Active,
		)

		status := user.Status
		err = user.UpdateStatus(
			context.Background(),
			conn.Conn(),
			99,
		)

		require.Error(t, err, "update status")
		require.Equal(t, status, user.Status, "status unchanged")
	})
}
