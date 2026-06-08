package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/app"
	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
	"github.com/RastBast/ordermesh-/internal/security/auth"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// OrderService is the subset of the application service the handler needs.
type OrderService interface {
	CreateOrder(ctx context.Context, in app.CreateOrderInput) (*domain.Order, error)
	GetOrder(ctx context.Context, id uuid.UUID) (*domain.Order, error)
	ListOrders(ctx context.Context, f ports.ListFilter) ([]*domain.Order, error)
	ChangeStatus(ctx context.Context, id uuid.UUID, target domain.Status) (*domain.Order, error)
}

// Handler holds dependencies for the order HTTP endpoints.
type Handler struct {
	svc OrderService
	log *slog.Logger
}

// NewHandler constructs the order handler.
func NewHandler(svc OrderService, log *slog.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// CreateOrder handles POST /v1/orders. Requires orders.create. The order is
// always created for the authenticated subject (the client cannot create
// orders on behalf of arbitrary customers).
func (h *Handler) CreateOrder(w http.ResponseWriter, r *http.Request) {
	principal := auth.FromContext(r.Context())
	if principal == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var req createOrderRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// ABAC: the customer id is derived from the verified subject, not trusted
	// from the body, preventing privilege escalation / impersonation.
	customerID, err := uuid.Parse(principal.Subject)
	if err != nil {
		// Subjects that are not UUIDs (e.g. service accounts) must specify a
		// customer explicitly AND hold an elevated permission.
		if !principal.Has(auth.PermOrdersUpdateAny) {
			writeError(w, http.StatusForbidden, "forbidden", "cannot determine order owner")
			return
		}
		customerID, err = uuid.Parse(req.CustomerID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_customer_id", "customer_id must be a valid uuid")
			return
		}
	}

	items := make([]app.CreateOrderItem, 0, len(req.Items))
	for _, it := range req.Items {
		items = append(items, app.CreateOrderItem{
			SKU: it.SKU, Name: it.Name, Quantity: it.Quantity,
			UnitPrice: it.UnitPrice, Currency: it.Currency,
		})
	}

	order, err := h.svc.CreateOrder(r.Context(), app.CreateOrderInput{
		CustomerID:    customerID,
		Items:         items,
		PaymentMethod: req.PaymentMethod,
		Contact: domain.ContactInfo{
			FullName: req.Contact.FullName,
			Email:    req.Contact.Email,
			Phone:    req.Contact.Phone,
		},
		ShippingAddress: domain.ShippingAddress{
			Line1:      req.ShippingAddress.Line1,
			Line2:      req.ShippingAddress.Line2,
			City:       req.ShippingAddress.City,
			PostalCode: req.ShippingAddress.PostalCode,
			Country:    req.ShippingAddress.Country,
		},
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		h.writeDomainError(w, err)
		return
	}
	// The creator may see their own PII unmasked.
	writeJSON(w, http.StatusCreated, toOrderResponse(order, true))
}

// GetOrder handles GET /v1/orders/{id}. ABAC: owners with orders.read.own, or
// elevated callers with orders.read.any.
func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
	principal := auth.FromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "id must be a valid uuid")
		return
	}
	order, err := h.svc.GetOrder(r.Context(), id)
	if err != nil {
		h.writeDomainError(w, err)
		return
	}

	owner := isOwner(principal, order)
	canReadAny := principal.Has(auth.PermOrdersReadAny)
	if !owner && !canReadAny {
		// Do not reveal existence to unauthorized callers — return 404.
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	// Full PII only for owner or elevated reader (support sees masked unless
	// they also hold update.any — least privilege by default).
	unmask := owner || principal.Has(auth.PermOrdersUpdateAny)
	writeJSON(w, http.StatusOK, toOrderResponse(order, unmask))
}

// ListOrders handles GET /v1/orders. Requires orders.list.any (support/admin);
// customers list their own via the implicit subject filter.
func (h *Handler) ListOrders(w http.ResponseWriter, r *http.Request) {
	principal := auth.FromContext(r.Context())
	q := r.URL.Query()
	f := ports.ListFilter{
		Limit:  atoiDefault(q.Get("limit"), 50),
		Offset: atoiDefault(q.Get("offset"), 0),
	}

	canListAny := principal.Has(auth.PermOrdersListAny)
	if !canListAny {
		// Customers may only list their own orders.
		if sub, err := uuid.Parse(principal.Subject); err == nil {
			f.CustomerID = &sub
		} else {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
	} else if cid := q.Get("customer_id"); cid != "" {
		parsed, err := uuid.Parse(cid)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_customer_id", "customer_id must be a valid uuid")
			return
		}
		f.CustomerID = &parsed
	}

	if s := q.Get("status"); s != "" {
		st := domain.Status(s)
		if !st.Valid() {
			writeError(w, http.StatusBadRequest, "invalid_status", "unknown status")
			return
		}
		f.Status = &st
	}

	orders, err := h.svc.ListOrders(r.Context(), f)
	if err != nil {
		h.writeDomainError(w, err)
		return
	}
	unmask := principal.Has(auth.PermOrdersUpdateAny)
	resp := listResponse{Items: make([]orderResponse, 0, len(orders))}
	for _, o := range orders {
		resp.Items = append(resp.Items, toOrderResponse(o, unmask || isOwner(principal, o)))
	}
	resp.Count = len(resp.Items)
	writeJSON(w, http.StatusOK, resp)
}

// ChangeStatus handles PATCH /v1/orders/{id}/status. ABAC ownership enforced.
func (h *Handler) ChangeStatus(w http.ResponseWriter, r *http.Request) {
	principal := auth.FromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "id must be a valid uuid")
		return
	}

	// Load first to evaluate ownership before mutating.
	existing, err := h.svc.GetOrder(r.Context(), id)
	if err != nil {
		h.writeDomainError(w, err)
		return
	}
	owner := isOwner(principal, existing)
	if !owner && !principal.Has(auth.PermOrdersUpdateAny) {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	if owner && !principal.Has(auth.PermOrdersUpdateOwn) && !principal.Has(auth.PermOrdersUpdateAny) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}

	var req changeStatusRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	target := domain.Status(req.Status)
	order, err := h.svc.ChangeStatus(r.Context(), id, target)
	if err != nil {
		h.writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrderResponse(order, owner || principal.Has(auth.PermOrdersUpdateAny)))
}

// isOwner reports whether the principal's subject matches the order's customer.
func isOwner(p *auth.Principal, o *domain.Order) bool {
	if p == nil {
		return false
	}
	sub, err := uuid.Parse(p.Subject)
	if err != nil {
		return false
	}
	return sub == o.CustomerID
}

// writeDomainError maps domain/application errors to HTTP responses.
func (h *Handler) writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrOrderNotFound):
		writeError(w, http.StatusNotFound, "not_found", "order not found")
	case errors.Is(err, domain.ErrInvalidTransition), errors.Is(err, domain.ErrTransitionFromFinal):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	case app.IsConflict(err):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, domain.ErrEmptyItems),
		errors.Is(err, domain.ErrInvalidQuantity),
		errors.Is(err, domain.ErrInvalidPrice),
		errors.Is(err, domain.ErrInvalidCustomer),
		errors.Is(err, domain.ErrCurrencyMismatch),
		errors.Is(err, domain.ErrInvalidContact),
		errors.Is(err, domain.ErrInvalidAddress),
		errors.Is(err, domain.ErrInvalidPayment),
		errors.Is(err, domain.ErrTooManyItems):
		writeError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
	default:
		h.log.Error("unhandled error", slog.Any("err", err))
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

// --- helpers ---

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is empty")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorResponse{Error: errorBody{Code: code, Message: msg}})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
