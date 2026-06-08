// Package ports declares the interfaces (driven ports) the application core
// depends on. Adapters in internal/adapters implement these. This is the
// dependency-inversion boundary of the hexagonal architecture.
package ports

import (
	"context"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/domain"
)

// TxFunc runs inside a single database transaction. The provided Repository
// and Outbox are bound to that transaction, guaranteeing atomic writes of the
// aggregate and its outbox events.
type TxFunc func(ctx context.Context, repo Repository, outbox Outbox) error

// UnitOfWork executes a function transactionally. Implementations must roll
// back on error and on panic.
type UnitOfWork interface {
	Do(ctx context.Context, fn TxFunc) error
}

// Repository persists and loads order aggregates.
type Repository interface {
	Create(ctx context.Context, o *domain.Order) error
	// GetByID returns ErrOrderNotFound if absent.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Order, error)
	// Update applies an optimistic-locked update; returns ErrOptimisticLock
	// when the stored version does not match expectedVersion.
	Update(ctx context.Context, o *domain.Order, expectedVersion int64) error
	List(ctx context.Context, f ListFilter) ([]*domain.Order, error)
}

// ListFilter is a simple keyset/limit filter for listing orders.
type ListFilter struct {
	CustomerID *uuid.UUID
	Status     *domain.Status
	Limit      int
	Offset     int
}

// Outbox stores domain events in the same transaction as the aggregate change
// (transactional outbox pattern), to be relayed to the broker later.
type Outbox interface {
	Add(ctx context.Context, e domain.Event) error
}

// OutboxStore is used by the background relay to drain pending events.
type OutboxStore interface {
	// FetchUnpublished locks and returns a batch of unpublished events
	// (FOR UPDATE SKIP LOCKED), allowing multiple relay workers.
	FetchUnpublished(ctx context.Context, limit int) ([]OutboxRecord, error)
	MarkPublished(ctx context.Context, ids []uuid.UUID) error
}

// OutboxRecord is a stored outbox row.
type OutboxRecord struct {
	Event domain.Event
}

// Publisher emits events to the message broker (Kafka).
type Publisher interface {
	Publish(ctx context.Context, e domain.Event) error
	Close() error
}

// Cache is a read-through cache for order aggregates (Redis).
type Cache interface {
	GetOrder(ctx context.Context, id uuid.UUID) (*domain.Order, bool, error)
	SetOrder(ctx context.Context, o *domain.Order) error
	DeleteOrder(ctx context.Context, id uuid.UUID) error
}
