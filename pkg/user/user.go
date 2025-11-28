/*
Package user provides utilities to create, read, and update
rows in the `users` database table.
*/
package user

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"grokloc.com/pkg/model/role"
	"grokloc.com/pkg/security/crypt"
	"grokloc.com/pkg/security/digest"
	"grokloc.com/pkg/security/key"
	"grokloc.com/pkg/security/password"
)

const (
	SchemaVersion = 0
)

type User struct {
	// PII fields are encrypted for storage and decrypted at read.
	// Corresponding digest fields are digests of decrypted PII.

	ID                  uuid.UUID `db:"id"`           // Generated.
	DisplayName         string    `db:"display_name"` // PII.
	DisplayNameDigest   string    `db:"display_name_digest"`
	Ed25519Public       string    `db:"ed25519_public"` // PII.
	Ed25519PublicDigest string    `db:"ed25519_public_digest"`
	Email               string    `db:"email"` // PII.
	EmailDigest         string    `db:"email_digest"`
	KeyVersion          uuid.UUID `db:"key_version"`
	Org                 uuid.UUID `db:"org"`
	Password            string    `db:"password"` // Argon2 hash.

	// Metadata.
	Ctime         int64     `db:"ctime"` // Unixtime.
	Mtime         int64     `db:"mtime"` // Unixtime.
	InsertOrder   int64     `db:"insert_order"`
	Role          int       `db:"role"`
	SchemaVersion int       `db:"schema_version"`
	Signature     uuid.UUID `db:"signature"` // Generated.
	Status        int       `db:"status"`
}

// Insert adds a new User to the database and returns it.
func Insert(
	ctx context.Context,
	conn *pgx.Conn,
	versionedKey key.Versioned,
	displayName string,
	ed25519Public string,
	email string,
	org uuid.UUID,
	password string,
	role int,
	schemaVersion int,
	status int,
) (*User, error) {
	encryptedDisplayName, err := crypt.Encrypt(displayName, versionedKey.Key)
	if err != nil {
		return nil, err
	}
	encryptedEd25519Public, err := crypt.Encrypt(ed25519Public, versionedKey.Key)
	if err != nil {
		return nil, err
	}
	encryptedEmail, err := crypt.Encrypt(email, versionedKey.Key)
	if err != nil {
		return nil, err
	}

	const insertQuery = `
	insert into users
	(display_name,
	display_name_digest,
	ed25519_public,
	ed25519_public_digest,
	email,
	email_digest,
	key_version,
	org,
	password,
	role,
	schema_version,
	status)
	values
	($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	returning id
	`

	var id uuid.UUID

	err = conn.QueryRow(ctx, insertQuery,
		encryptedDisplayName,
		digest.SHA256Hex(displayName),
		encryptedEd25519Public,
		digest.SHA256Hex(ed25519Public),
		encryptedEmail,
		digest.SHA256Hex(email),
		versionedKey.Version,
		org,
		password,
		role,
		schemaVersion,
		status,
	).Scan(&id)
	if err != nil {
		return nil, err
	}

	m := make(key.VersionedMap)
	m[versionedKey.Version] = versionedKey.Key
	return Read(ctx, conn, m, id)
}

// Read selects the users row matching `id` and decrypts PII fields.
func Read(
	ctx context.Context,
	conn *pgx.Conn,
	m key.VersionedMap,
	id uuid.UUID,
) (*User, error) {
	const query = `select * from users where id = @id`
	args := pgx.NamedArgs{"id": id}
	rows, err := conn.Query(ctx, query, args)
	if err != nil {
		return nil, err
	}
	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return nil, err
	}

	versionedKey, err := m.Get(user.KeyVersion)
	if err != nil {
		return nil, err
	}

	// Decrypt PII columns.

	user.DisplayName, err = crypt.Decrypt(
		user.DisplayName,
		user.DisplayNameDigest,
		versionedKey.Key,
	)
	if err != nil {
		return nil, err
	}

	user.Ed25519Public, err = crypt.Decrypt(
		user.Ed25519Public,
		user.Ed25519PublicDigest,
		versionedKey.Key,
	)
	if err != nil {
		return nil, err
	}

	user.Email, err = crypt.Decrypt(
		user.Email,
		user.EmailDigest,
		versionedKey.Key,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *User) NewEd25519(
	ctx context.Context,
	conn *pgx.Conn,
	versionedKey key.Versioned,
	ed25519Public string,
) error {
	encryptedEd25519Public, err := crypt.Encrypt(ed25519Public, versionedKey.Key)
	if err != nil {
		return err
	}

	const query = `update users 
		set ed25519_public = $1, 
		ed25519_public_digest = $2
		where id = $3
		returning mtime, signature, ed25519_public_digest`

	err = conn.QueryRow(
		ctx,
		query,
		encryptedEd25519Public,
		digest.SHA256Hex(ed25519Public),
		u.ID,
	).
		Scan(
			&u.Mtime,
			&u.Signature,
			&u.Ed25519PublicDigest,
		)

	if err != nil {
		return err
	}

	u.Ed25519Public = ed25519Public
	return nil
}

func (u *User) UpdateStatus(
	ctx context.Context,
	conn *pgx.Conn,
	status int,
) error {
	const query = `update users 
		set status = $1 
		where id = $2
		returning mtime, signature, status`

	return conn.QueryRow(ctx, query, status, u.ID).Scan(&u.Mtime, &u.Signature, &u.Status)
}

// ForTest creates a new instance of a User for test automation only.
func ForTest(
	ctx context.Context,
	conn *pgx.Conn,
	versionKey key.Versioned,
	org uuid.UUID,
	status int,
) *User {
	ed25519Public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err.Error())
	}
	u, err := Insert(
		context.Background(),
		conn,
		versionKey,
		uuid.NewString(), // display name
		hex.EncodeToString(ed25519Public),
		uuid.NewString(),  // email
		uuid.New(),        // org
		password.Random(), // password
		role.Test,
		SchemaVersion,
		status,
	)
	if err != nil {
		panic(err.Error())
	}
	return u
}
