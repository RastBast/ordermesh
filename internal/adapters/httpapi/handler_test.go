package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/app"
	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
	"github.com/RastBast/ordermesh-/internal/platform/observability"
	"github.com/RastBast/ordermesh-/internal/security/auth"
	"github.com/prometheus/client_golang/prometheus"
)

// stubService implements OrderService for handler tests.
type stubService struct {
	createFn func(ctx context.Context, in app.CreateOrderInput) (*domain.Order, error)
	getFn    func(ctx context.Context, id uuid.UUID) (*domain.Order, error)
}

func (s stubService) CreateOrder(ctx context.Context, in app.CreateOrderInput) (*domain.Order, error) {
	return s.createFn(ctx, in)
}
func (s stubService) GetOrder(ctx context.Context, id uuid.UUID) (*domain.Order, error) {
	return s.getFn(ctx, id)
}
func (s stubService) ListOrders(ctx context.Context, f ports.ListFilter) ([]*domain.Order, error) {
	return nil, nil
}
func (s stubService) ChangeStatus(ctx context.Context, id uuid.UUID, t domain.Status) (*domain.Order, error) {
	return nil, nil
}

func newTestRouter(svc OrderService) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := observability.NewMetrics(prometheus.NewRegistry())
	return NewRouter(RouterDeps{
		Handler: NewHandler(svc, log),
		Metrics: m,
		Log:     log,
		// Verifier nil -> auth middleware skipped; we inject the principal
		// directly via withPrincipal so handler ABAC logic is still exercised.
	})
}

// withPrincipal injects an authenticated principal into the request context,
// emulating what AuthMiddleware would do.
func withPrincipal(req *http.Request, p *auth.Principal) *http.Request {
	return req.WithContext(auth.WithPrincipal(req.Context(), p))
}

func sampleBody(customerID uuid.UUID) string {
	return `{
		"customer_id":"` + customerID.String() + `",
		"payment_method":"CARD",
		"contact":{"full_name":"Ada Lovelace","email":"ada@example.com","phone":"+1 415 555 1234"},
		"shipping_address":{"line1":"1 Main St","city":"London","postal_code":"EC1","country":"GB"},
		"items":[{"sku":"S1","name":"W","quantity":2,"unit_price":1500,"currency":"USD"}]
	}`
}

func TestCreateOrder_Created(t *testing.T) {
	t.Parallel()
	customerID := uuid.New()
	svc := stubService{
		createFn: func(_ context.Context, in app.CreateOrderInput) (*domain.Order, error) {
			return domain.NewOrder(domain.NewOrderInput{
				CustomerID: in.CustomerID,
				Items: []domain.Item{
					{SKU: in.Items[0].SKU, Quantity: in.Items[0].Quantity, UnitPrice: in.Items[0].UnitPrice, Currency: in.Items[0].Currency},
				},
				PaymentMethod:   domain.PaymentMethod(in.PaymentMethod),
				Contact:         in.Contact,
				ShippingAddress: in.ShippingAddress,
				IdempotencyKey:  in.IdempotencyKey,
			})
		},
	}
	router := newTestRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(sampleBody(customerID)))
	req = withPrincipal(req, auth.NewPrincipal(customerID.String(), auth.PermOrdersCreate))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp orderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "PENDING" || resp.TotalPrice != 3000 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	// Creator sees their own PII unmasked.
	if resp.Contact.Email != "ada@example.com" {
		t.Fatalf("owner should see unmasked email, got %q", resp.Contact.Email)
	}
}

func TestCreateOrder_Unauthenticated(t *testing.T) {
	t.Parallel()
	router := newTestRouter(stubService{})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(sampleBody(uuid.New())))
	// no principal injected
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestGetOrder_NotFound(t *testing.T) {
	t.Parallel()
	svc := stubService{
		getFn: func(_ context.Context, _ uuid.UUID) (*domain.Order, error) {
			return nil, domain.ErrOrderNotFound
		},
	}
	router := newTestRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+uuid.New().String(), nil)
	req = withPrincipal(req, auth.NewPrincipal(uuid.New().String(), auth.PermOrdersReadOwn))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestGetOrder_NonOwnerGets404(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	order, _ := domain.NewOrder(domain.NewOrderInput{
		CustomerID:      owner,
		Items:           []domain.Item{{SKU: "S1", Quantity: 1, UnitPrice: 100, Currency: "USD"}},
		PaymentMethod:   domain.PaymentCard,
		Contact:         domain.ContactInfo{FullName: "Ada Lovelace", Email: "ada@example.com", Phone: "+1 415 555 1234"},
		ShippingAddress: domain.ShippingAddress{Line1: "1 Main St", City: "London", PostalCode: "EC1", Country: "GB"},
	})
	svc := stubService{getFn: func(_ context.Context, _ uuid.UUID) (*domain.Order, error) { return order, nil }}
	router := newTestRouter(svc)

	// A different customer (not owner, no read.any) must get 404, not the data.
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+order.ID.String(), nil)
	req = withPrincipal(req, auth.NewPrincipal(uuid.New().String(), auth.PermOrdersReadOwn))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-owner, got %d", rec.Code)
	}
}

func TestGetOrder_SupportSeesMaskedPII(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	order, _ := domain.NewOrder(domain.NewOrderInput{
		CustomerID:      owner,
		Items:           []domain.Item{{SKU: "S1", Quantity: 1, UnitPrice: 100, Currency: "USD"}},
		PaymentMethod:   domain.PaymentCard,
		Contact:         domain.ContactInfo{FullName: "Ada Lovelace", Email: "ada@example.com", Phone: "+1 415 555 1234"},
		ShippingAddress: domain.ShippingAddress{Line1: "1 Main St", City: "London", PostalCode: "EC1", Country: "GB"},
	})
	svc := stubService{getFn: func(_ context.Context, _ uuid.UUID) (*domain.Order, error) { return order, nil }}
	router := newTestRouter(svc)

	// Support role: read.any but NOT update.any -> PII masked.
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+order.ID.String(), nil)
	req = withPrincipal(req, auth.NewPrincipal("support-agent", auth.PermOrdersReadAny))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp orderResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Contact.Email == "ada@example.com" {
		t.Fatalf("support must see masked email, got plaintext")
	}
	if resp.Contact.Email != "a***@***.com" {
		t.Fatalf("unexpected masked email: %q", resp.Contact.Email)
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	router := newTestRouter(stubService{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}
