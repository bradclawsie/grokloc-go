/*
Package postgresql provides utilties for decoding errors.
*/
package postgresql

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrRowsAffected = errors.New("query rows affected")
)

// UniqueConstraint will try to match the db unique constraint violation.
func UniqueConstraint(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// https://www.postgresql.org/docs/current/errcodes-appendix.html
		return pgErr.Code == "23505"
	}
	return false
}

// NotNullConstraint will try to match the db not-null constraint violation.
func NotNullConstraint(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// https://www.postgresql.org/docs/current/errcodes-appendix.html
		return pgErr.Code == "23502"
	}
	return false
}
