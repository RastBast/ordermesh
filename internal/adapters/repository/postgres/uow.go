// Package postgres implements the persistence ports on top of pgx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RastBast/ordermesh-/internal/ports"
)

// querier abstracts *pgxpool.Pool and pgx.Tx for shared query code.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Encryptor seals/opens PII for storage at rest. The order id is passed as
// associated data to bind ciphertext to its row.
type Encryptor interface {
	EncryptString(plaintext, aad string) (string, error)
	DecryptString(encoded, aad string) (string, error)
}

// UnitOfWork implements ports.UnitOfWork using a pgx transaction. Repository
// and Outbox bound to the transaction are passed to the callback.
type UnitOfWork struct {
	pool *pgxpool.Pool
	enc  Encryptor
}

// NewUnitOfWork constructs the unit of work from a pool and a PII encryptor.
func NewUnitOfWork(pool *pgxpool.Pool, enc Encryptor) *UnitOfWork {
	return &UnitOfWork{pool: pool, enc: enc}
}

// Do runs fn inside a read-committed transaction, rolling back on error or panic.
func (u *UnitOfWork) Do(ctx context.Context, fn ports.TxFunc) (err error) {
	tx, err := u.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				err = fmt.Errorf("%w; rollback: %v", err, rbErr)
			}
		}
	}()

	repo := &Repository{q: tx, enc: u.enc}
	outbox := &OutboxRepository{q: tx}

	if err = fn(ctx, repo, outbox); err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
