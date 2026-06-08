package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/ports"
)

// Relay is the transactional-outbox dispatcher. It periodically drains
// unpublished events and pushes them to the broker, then marks them published.
// Delivery is at-least-once; consumers must be idempotent (events carry a
// stable id, and Kafka keys preserve per-aggregate ordering).
type Relay struct {
	store        ports.OutboxStore
	publisher    ports.Publisher
	log          *slog.Logger
	pollInterval time.Duration
	batchSize    int

	onPublished func(eventType string)
	onPending   func(n int)
}

// RelayOption customises the relay.
type RelayOption func(*Relay)

// WithPublishedHook registers a callback fired per published event (metrics).
func WithPublishedHook(fn func(eventType string)) RelayOption {
	return func(r *Relay) { r.onPublished = fn }
}

// NewRelay constructs the relay worker.
func NewRelay(store ports.OutboxStore, publisher ports.Publisher, log *slog.Logger, pollInterval time.Duration, batchSize int, opts ...RelayOption) *Relay {
	r := &Relay{
		store:        store,
		publisher:    publisher,
		log:          log,
		pollInterval: pollInterval,
		batchSize:    batchSize,
		onPublished:  func(string) {},
		onPending:    func(int) {},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run blocks, draining the outbox until ctx is cancelled.
func (r *Relay) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	r.log.Info("outbox relay started", slog.Duration("interval", r.pollInterval), slog.Int("batch", r.batchSize))

	for {
		select {
		case <-ctx.Done():
			r.log.Info("outbox relay stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := r.drain(ctx); err != nil {
				r.log.Error("outbox drain failed", slog.Any("err", err))
			}
		}
	}
}

// drain processes a single batch. It keeps looping while full batches are
// returned so a backlog is cleared quickly.
func (r *Relay) drain(ctx context.Context) error {
	for {
		records, err := r.store.FetchUnpublished(ctx, r.batchSize)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}

		published := make([]uuid.UUID, 0, len(records))
		for _, rec := range records {
			if err := r.publisher.Publish(ctx, rec.Event); err != nil {
				r.log.Error("publish failed; will retry",
					slog.String("event_id", rec.Event.ID.String()),
					slog.String("type", string(rec.Event.Type)),
					slog.Any("err", err))
				break // stop the batch; unpublished rows stay for next tick
			}
			published = append(published, rec.Event.ID)
			r.onPublished(string(rec.Event.Type))
		}

		if len(published) > 0 {
			if err := r.store.MarkPublished(ctx, published); err != nil {
				return err
			}
		}

		if len(records) < r.batchSize {
			return nil
		}
	}
}
