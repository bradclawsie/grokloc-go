/*
Package org provides utilities to create, read, and update
rows in the `orgs` database table.
*/
package org

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"grokloc.com/pkg/model/role"
	pkg_status "grokloc.com/pkg/model/status"
	"grokloc.com/pkg/postgresql"
	"grokloc.com/pkg/security/key"
	"grokloc.com/pkg/security/password"
	"grokloc.com/pkg/user"
)

const (
	SchemaVersion = 0
)

type Org struct {
	ID    uuid.UUID `db:"id"` // Generated.
	Name  string    `db:"name"`
	Owner uuid.UUID `db:"owner"`

	// Metadata.
	Ctime         int64     `db:"ctime"` // Unixtime.
	Mtime         int64     `db:"mtime"` // Unixtime.
	InsertOrder   int64     `db:"insert_order"`
	Role          int       `db:"role"`
	SchemaVersion int       `db:"schema_version"`
	Signature     uuid.UUID `db:"signature"` // Generated.
	Status        int       `db:"status"`
}

func Insert(
	ctx context.Context,
	conn *pgx.Conn,
	name string,
	ownerVersionKey key.Versioned,
	ownerDisplayName string,
	ownerEd25519Public string,
	ownerEmail string,
	ownerPassword string,
	role int,
	schemaVersion int,
	status int,
) (*Org, *user.User, error) {
	id := uuid.New()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	// Owner is initially unconfirmed until org
	// itself is inserted.
	owner, err := user.Insert(
		ctx,
		conn,
		ownerVersionKey,
		ownerDisplayName,
		ownerEd25519Public,
		ownerEmail,
		id,
		ownerPassword,
		role,
		user.SchemaVersion,
		pkg_status.Unconfirmed,
	)
	if err != nil {
		return nil, nil, err
	}

	const query = `
	insert into orgs
	(id, name, owner, role, schema_version, status)
	values
	($1, $2, $3, $4, $5, $6)
	`

	result, err := tx.Exec(
		ctx,
		query,
		id, name, owner.ID, role, SchemaVersion, status,
	)
	if err != nil {
		return nil, nil, err
	}
	if result.RowsAffected() != 1 {
		return nil, nil, postgresql.ErrRowsAffected
	}

	org, err := Read(ctx, tx.Conn(), id)
	if err != nil {
		return nil, nil, err
	}

	// Now that org is inserted, make owner active.
	err = owner.UpdateStatus(ctx, tx.Conn(), pkg_status.Active)
	if err != nil {
		return nil, nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, nil, err
	}

	return org, owner, nil
}

func Read(
	ctx context.Context,
	conn *pgx.Conn,
	id uuid.UUID,
) (*Org, error) {
	const query = `select * from orgs where id = @id`
	args := pgx.NamedArgs{"id": id}
	rows, err := conn.Query(ctx, query, args)
	if err != nil {
		return nil, err
	}
	org, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Org])
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (o *Org) UpdateStatus(
	ctx context.Context,
	conn *pgx.Conn,
	status int,
) error {
	const query = `update orgs
		set status = $1 
		where id = $2
		returning mtime, signature, status`

	return conn.QueryRow(ctx, query, status, o.ID).Scan(&o.Mtime, &o.Signature, &o.Status)
}

// ForTest creates a new instance of a Org for test automation only.
func ForTest(
	ctx context.Context,
	conn *pgx.Conn,
	ownerVersionKey key.Versioned,
	status int,
) (*Org, *user.User) {
	ownerEd25519Public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err.Error())
	}
	org, owner, err := Insert(
		context.Background(),
		conn,
		uuid.NewString(),
		ownerVersionKey,
		uuid.NewString(), // owner display name
		hex.EncodeToString(ownerEd25519Public),
		uuid.NewString(),  // owner email
		password.Random(), // password
		role.Test,
		SchemaVersion,
		status,
	)
	if err != nil {
		panic(err.Error())
	}
	return org, owner
}
