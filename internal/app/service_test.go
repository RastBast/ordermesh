package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// --- in-memory fakes implementing the ports ---

type memRepo struct {
	mu     sync.Mutex
	orders map[uuid.UUID]*domain.Order
}

func newMemRepo() *memRepo { return &memRepo{orders: map[uuid.UUID]*domain.Order{}} }

func (r *memRepo) Create(_ context.Context, o *domain.Order) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.orders[o.ID]; ok {
		return domain.ErrOrderAlreadyExists
	}
	cp := *o
	r.orders[o.ID] = &cp
	return nil
}

func (r *memRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.orders[id]
	if !ok {
		return nil, domain.ErrOrderNotFound
	}
	cp := *o
	return &cp, nil
}

func (r *memRepo) Update(_ context.Context, o *domain.Order, expected int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.orders[o.ID]
	if !ok {
		return domain.ErrOrderNotFound
	}
	if cur.Version != expected {
		return domain.ErrOptimisticLock
	}
	cp := *o
	r.orders[o.ID] = &cp
	return nil
}

func (r *memRepo) List(_ context.Context, f ports.ListFilter) ([]*domain.Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.Order
	for _, o := range r.orders {
		if f.Status != nil && o.Status != *f.Status {
			continue
		}
		cp := *o
		out = append(out, &cp)
	}
	return out, nil
}

type memOutbox struct {
	mu     sync.Mutex
	events []domain.Event
}

func (o *memOutbox) Add(_ context.Context, e domain.Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
	return nil
}

// memUoW runs fn against shared repo/outbox with naive all-or-nothing semantics.
type memUoW struct {
	repo   *memRepo
	outbox *memOutbox
}

func (u *memUoW) Do(ctx context.Context, fn ports.TxFunc) error {
	return fn(ctx, u.repo, u.outbox)
}

type memCache struct {
	mu   sync.Mutex
	data map[uuid.UUID]*domain.Order
}

func newMemCache() *memCache { return &memCache{data: map[uuid.UUID]*domain.Order{}} }

func (c *memCache) GetOrder(_ context.Context, id uuid.UUID) (*domain.Order, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.data[id]
	if !ok {
		return nil, false, nil
	}
	cp := *o
	return &cp, true, nil
}

func (c *memCache) SetOrder(_ context.Context, o *domain.Order) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *o
	c.data[o.ID] = &cp
	return nil
}

func (c *memCache) DeleteOrder(_ context.Context, id uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, id)
	return nil
}

func newTestService() (*Service, *memRepo, *memOutbox, *memCache) {
	repo := newMemRepo()
	outbox := &memOutbox{}
	cache := newMemCache()
	uow := &memUoW{repo: repo, outbox: outbox}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewService(uow, cache, log), repo, outbox, cache
}

func sampleInput() CreateOrderInput {
	return CreateOrderInput{
		CustomerID: uuid.New(),
		Items: []CreateOrderItem{
			{SKU: "SKU-1", Name: "Widget", Quantity: 2, UnitPrice: 1500, Currency: "USD"},
		},
		PaymentMethod:   "CARD",
		Contact:         domain.ContactInfo{FullName: "Ada Lovelace", Email: "ada@example.com", Phone: "+1 415 555 1234"},
		ShippingAddress: domain.ShippingAddress{Line1: "1 Main St", City: "London", PostalCode: "EC1", Country: "GB"},
		IdempotencyKey:  "idem-1",
	}
}

func TestCreateOrder_PersistsAndEmitsEvent(t *testing.T) {
	t.Parallel()
	svc, repo, outbox, cache := newTestService()

	o, err := svc.CreateOrder(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := repo.orders[o.ID]; !ok {
		t.Fatal("order not persisted")
	}
	if len(outbox.events) != 1 || outbox.events[0].Type != domain.EventOrderCreated {
		t.Fatalf("expected one order.created event, got %+v", outbox.events)
	}
	if _, ok := cache.data[o.ID]; !ok {
		t.Fatal("cache not warmed")
	}
}

func TestCreateOrder_ValidationError(t *testing.T) {
	t.Parallel()
	svc, _, outbox, _ := newTestService()

	in := sampleInput()
	in.Items = nil
	_, err := svc.CreateOrder(context.Background(), in)
	if !errors.Is(err, domain.ErrEmptyItems) {
		t.Fatalf("want ErrEmptyItems, got %v", err)
	}
	if len(outbox.events) != 0 {
		t.Fatal("no event should be emitted on validation error")
	}
}

func TestChangeStatus_HappyPath(t *testing.T) {
	t.Parallel()
	svc, _, outbox, cache := newTestService()

	o, _ := svc.CreateOrder(context.Background(), sampleInput())
	updated, err := svc.ChangeStatus(context.Background(), o.ID, domain.StatusPaid)
	if err != nil {
		t.Fatalf("change status: %v", err)
	}
	if updated.Status != domain.StatusPaid {
		t.Fatalf("want PAID, got %s", updated.Status)
	}
	if updated.Version != 2 {
		t.Fatalf("want version 2, got %d", updated.Version)
	}
	// order.created + order.paid
	if len(outbox.events) != 2 || outbox.events[1].Type != domain.EventOrderPaid {
		t.Fatalf("unexpected events: %+v", outbox.events)
	}
	if _, ok := cache.data[o.ID]; ok {
		t.Fatal("cache should be invalidated after status change")
	}
}

func TestChangeStatus_InvalidTransition(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newTestService()

	o, _ := svc.CreateOrder(context.Background(), sampleInput())
	_, err := svc.ChangeStatus(context.Background(), o.ID, domain.StatusShipped)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("want ErrInvalidTransition, got %v", err)
	}
}

func TestGetOrder_NotFound(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newTestService()
	_, err := svc.GetOrder(context.Background(), uuid.New())
	if !errors.Is(err, domain.ErrOrderNotFound) {
		t.Fatalf("want ErrOrderNotFound, got %v", err)
	}
}
