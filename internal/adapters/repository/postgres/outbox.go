package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// OutboxRepository implements ports.Outbox bound to a transaction.
type OutboxRepository struct {
	q querier
}

// Add stores an event into the outbox within the current transaction.
func (o *OutboxRepository) Add(ctx context.Context, e domain.Event) error {
	const q = `
		INSERT INTO outbox (id, aggregate_id, aggregate_type, type, payload, occurred_at, published)
		VALUES ($1, $2, $3, $4, $5, $6, false)`
	_, err := o.q.Exec(ctx, q, e.ID, e.AggregateID, e.AggregateType, e.Type, e.Payload, e.OccurredAt)
	if err != nil {
		return fmt.Errorf("insert outbox: %w", err)
	}
	return nil
}

// OutboxStore implements ports.OutboxStore for the background relay using the pool.
type OutboxStore struct {
	pool *pgxpool.Pool
}

// NewOutboxStore constructs the relay store.
func NewOutboxStore(pool *pgxpool.Pool) *OutboxStore {
	return &OutboxStore{pool: pool}
}

// FetchUnpublished locks and returns a batch of unpublished events using
// FOR UPDATE SKIP LOCKED so multiple relay workers can run concurrently.
// The caller is expected to MarkPublished after a successful publish; the
// lock is held only for the duration of this short transaction, so we instead
// return the rows and rely on the published flag for idempotency.
func (s *OutboxStore) FetchUnpublished(ctx context.Context, limit int) ([]ports.OutboxRecord, error) {
	const q = `
		SELECT id, aggregate_id, aggregate_type, type, payload, occurred_at
		FROM outbox
		WHERE published = false
		ORDER BY occurred_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED`

	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch outbox: %w", err)
	}
	defer rows.Close()

	var out []ports.OutboxRecord
	for rows.Next() {
		var e domain.Event
		if err := rows.Scan(&e.ID, &e.AggregateID, &e.AggregateType, &e.Type, &e.Payload, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan outbox: %w", err)
		}
		out = append(out, ports.OutboxRecord{Event: e})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate outbox: %w", err)
	}
	return out, nil
}

// MarkPublished flags the given event ids as published.
func (s *OutboxStore) MarkPublished(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	const q = `UPDATE outbox SET published = true, published_at = now() WHERE id = ANY($1)`
	_, err := s.pool.Exec(ctx, q, ids)
	if err != nil {
		return fmt.Errorf("mark published: %w", err)
	}
	return nil
}

// CountPending returns the number of unpublished events (for metrics).
func (s *OutboxStore) CountPending(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM outbox WHERE published = false`
	var n int64
	if err := s.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending: %w", err)
	}
	return n, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// ensure interface compliance at compile time.
var (
	_ ports.Outbox      = (*OutboxRepository)(nil)
	_ ports.OutboxStore = (*OutboxStore)(nil)
	_ ports.Repository  = (*Repository)(nil)
	_ ports.UnitOfWork  = (*UnitOfWork)(nil)
)
