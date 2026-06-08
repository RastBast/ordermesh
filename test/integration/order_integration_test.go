//go:build integration

// Package integration contains end-to-end tests that spin up real Postgres and
// Redis using testcontainers. Run with: go test -tags=integration ./test/...
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	redisrepo "github.com/RastBast/ordermesh-/internal/adapters/cache/redisrepo"
	pgrepo "github.com/RastBast/ordermesh-/internal/adapters/repository/postgres"
	"github.com/RastBast/ordermesh-/internal/app"
	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
	"github.com/RastBast/ordermesh-/internal/security/crypto"

	cryptorand "crypto/rand"
	"io"
	"log/slog"
	"strings"
)

func containsSubstr(s, sub string) bool { return strings.Contains(s, sub) }

const schema = `
CREATE TABLE orders (
    id UUID PRIMARY KEY, customer_id UUID NOT NULL, status TEXT NOT NULL,
    items JSONB NOT NULL, total_price BIGINT NOT NULL, currency TEXT NOT NULL,
    payment_method TEXT NOT NULL,
    contact_enc TEXT NOT NULL, shipping_address_enc TEXT NOT NULL,
    ship_city TEXT NOT NULL, ship_country CHAR(2) NOT NULL,
    idempotency_key TEXT,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE outbox (
    id UUID PRIMARY KEY, aggregate_id UUID NOT NULL, aggregate_type TEXT NOT NULL,
    type TEXT NOT NULL, payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published BOOLEAN NOT NULL DEFAULT false, published_at TIMESTAMPTZ);`

func TestOrderLifecycle_Integration(t *testing.T) {
	ctx := context.Background()

	pgC, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase("orders"),
		postgres.WithUsername("order"),
		postgres.WithPassword("order"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pgC.Terminate(ctx) })

	pgDSN, err := pgC.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("pg dsn: %v", err)
	}

	redisC, err := tcredis.RunContainer(ctx, testcontainers.WithImage("redis:7-alpine"))
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = redisC.Terminate(ctx) })

	redisEndpoint, err := redisC.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("redis endpoint: %v", err)
	}

	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		t.Fatalf("pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, schema); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisEndpoint})
	t.Cleanup(func() { _ = rdb.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// PII encryption keyring (random 32-byte key for the test).
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypto.NewKeyring([][]byte{key})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	uow := pgrepo.NewUnitOfWork(pool, keyring)
	cache := redisrepo.New(rdb, time.Minute)
	svc := app.NewService(uow, cache, log)

	// Create
	order, err := svc.CreateOrder(ctx, app.CreateOrderInput{
		CustomerID: uuid.New(),
		Items: []app.CreateOrderItem{
			{SKU: "S1", Name: "Widget", Quantity: 2, UnitPrice: 1500, Currency: "USD"},
		},
		PaymentMethod:   "CARD",
		Contact:         domain.ContactInfo{FullName: "Ada Lovelace", Email: "ada@example.com", Phone: "+1 415 555 1234"},
		ShippingAddress: domain.ShippingAddress{Line1: "1 Main St", City: "London", PostalCode: "EC1", Country: "GB"},
		IdempotencyKey:  "itest-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create order: %v", err)
	}
	if order.TotalPrice != 3000 {
		t.Fatalf("want total 3000, got %d", order.TotalPrice)
	}

	// Verify PII is encrypted at rest: the raw column must not contain plaintext.
	var contactEnc string
	if err := pool.QueryRow(ctx, `SELECT contact_enc FROM orders WHERE id=$1`, order.ID).Scan(&contactEnc); err != nil {
		t.Fatalf("read contact_enc: %v", err)
	}
	if contactEnc == "" || containsSubstr(contactEnc, "ada@example.com") {
		t.Fatalf("contact PII is not encrypted at rest: %q", contactEnc)
	}

	// Get (cache warmed by create) — PII must round-trip via decryption.
	got, err := svc.GetOrder(ctx, order.ID)
	if err != nil || got.ID != order.ID {
		t.Fatalf("get order: %v", err)
	}
	if got.Contact.Email != "ada@example.com" {
		t.Fatalf("PII did not decrypt correctly: %q", got.Contact.Email)
	}

	// Transition PENDING -> PAID
	paid, err := svc.ChangeStatus(ctx, order.ID, domain.StatusPaid)
	if err != nil {
		t.Fatalf("change status: %v", err)
	}
	if paid.Status != domain.StatusPaid || paid.Version != 2 {
		t.Fatalf("unexpected: %+v", paid)
	}

	// Outbox should hold 2 events (created + paid)
	store := pgrepo.NewOutboxStore(pool)
	recs, err := store.FetchUnpublished(ctx, 10)
	if err != nil {
		t.Fatalf("fetch outbox: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 outbox events, got %d", len(recs))
	}

	ids := make([]uuid.UUID, 0, len(recs))
	for _, r := range recs {
		ids = append(ids, r.Event.ID)
	}
	if err := store.MarkPublished(ctx, ids); err != nil {
		t.Fatalf("mark published: %v", err)
	}
	pending, err := store.CountPending(ctx)
	if err != nil || pending != 0 {
		t.Fatalf("want 0 pending, got %d (err=%v)", pending, err)
	}

	// Invalid transition PAID -> PENDING
	if _, err := svc.ChangeStatus(ctx, order.ID, domain.StatusPending); err == nil {
		t.Fatal("expected invalid transition error")
	}

	var _ ports.OutboxStore = store
}
