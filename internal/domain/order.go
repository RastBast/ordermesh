package domain

import (
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Status represents the lifecycle state of an order.
type Status string

const (
	StatusPending   Status = "PENDING"
	StatusPaid      Status = "PAID"
	StatusShipped   Status = "SHIPPED"
	StatusCancelled Status = "CANCELLED"
)

// Valid reports whether the status is a known value.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusPaid, StatusShipped, StatusCancelled:
		return true
	default:
		return false
	}
}

// Domain-level errors. The transport layer maps these to protocol responses.
var (
	ErrOrderNotFound        = errors.New("order not found")
	ErrInvalidTransition    = errors.New("invalid status transition")
	ErrEmptyItems           = errors.New("order must contain at least one item")
	ErrInvalidQuantity      = errors.New("item quantity must be positive")
	ErrInvalidPrice         = errors.New("item price must be positive")
	ErrInvalidCustomer      = errors.New("customer id is required")
	ErrOrderAlreadyExists   = errors.New("order already exists")
	ErrOptimisticLock       = errors.New("order was modified concurrently")
	ErrTransitionFromFinal  = errors.New("cannot transition from a final state")
	ErrCurrencyMismatch     = errors.New("all items must share the same currency")
	ErrInvalidContact       = errors.New("invalid contact info")
	ErrInvalidAddress       = errors.New("invalid shipping address")
	ErrTooManyItems         = errors.New("order exceeds maximum item count")
	ErrInvalidPayment       = errors.New("invalid payment method")
)

// maxItems bounds an order to mitigate resource-exhaustion via huge payloads.
const maxItems = 100

// PaymentMethod enumerates supported payment methods (domain specifics).
type PaymentMethod string

const (
	PaymentCard   PaymentMethod = "CARD"
	PaymentPayPal PaymentMethod = "PAYPAL"
	PaymentApple  PaymentMethod = "APPLE_PAY"
)

// Valid reports whether the payment method is supported.
func (p PaymentMethod) Valid() bool {
	switch p {
	case PaymentCard, PaymentPayPal, PaymentApple:
		return true
	default:
		return false
	}
}

// Item is a single line in an order. Money is stored in minor units (cents).
type Item struct {
	SKU         string
	Name        string
	Quantity    int32
	UnitPrice   int64 // minor units, e.g. cents
	Currency    string
}

// Order is the aggregate root. PII (Contact, ShippingAddress) is encrypted at
// rest by the repository and masked in all logs/traces by the value objects.
type Order struct {
	ID            uuid.UUID
	CustomerID    uuid.UUID
	Status        Status
	Items         []Item
	TotalPrice    int64 // minor units
	Currency      string
	PaymentMethod PaymentMethod

	// PII — never logged in plaintext, encrypted in the database.
	Contact         ContactInfo
	ShippingAddress ShippingAddress

	// IdempotencyKey ties the creation request to this aggregate (audit trail).
	IdempotencyKey string

	Version   int64 // optimistic concurrency token
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LogValue ensures an Order logged directly never leaks PII.
func (o *Order) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", o.ID.String()),
		slog.String("customer_id", o.CustomerID.String()),
		slog.String("status", string(o.Status)),
		slog.Int64("total_price", o.TotalPrice),
		slog.String("currency", o.Currency),
		slog.Int64("version", o.Version),
		slog.Any("contact", o.Contact),
		slog.Any("shipping", o.ShippingAddress),
	)
}

// allowedTransitions encodes the order state machine.
var allowedTransitions = map[Status]map[Status]bool{
	StatusPending: {
		StatusPaid:      true,
		StatusCancelled: true,
	},
	StatusPaid: {
		StatusShipped:   true,
		StatusCancelled: true,
	},
	StatusShipped:   {}, // final
	StatusCancelled: {}, // final
}

// NewOrderInput carries the validated inputs for constructing an order,
// including the domain-specific PII and payment fields.
type NewOrderInput struct {
	CustomerID      uuid.UUID
	Items           []Item
	PaymentMethod   PaymentMethod
	Contact         ContactInfo
	ShippingAddress ShippingAddress
	IdempotencyKey  string
}

// NewOrder constructs a fully validated order in the PENDING state.
func NewOrder(in NewOrderInput) (*Order, error) {
	if in.CustomerID == uuid.Nil {
		return nil, ErrInvalidCustomer
	}
	if len(in.Items) == 0 {
		return nil, ErrEmptyItems
	}
	if len(in.Items) > maxItems {
		return nil, ErrTooManyItems
	}
	if !in.PaymentMethod.Valid() {
		return nil, ErrInvalidPayment
	}
	if err := in.Contact.Validate(); err != nil {
		return nil, err
	}
	if err := in.ShippingAddress.Validate(); err != nil {
		return nil, err
	}

	currency := in.Items[0].Currency
	var total int64
	for _, it := range in.Items {
		if it.Quantity <= 0 {
			return nil, ErrInvalidQuantity
		}
		if it.UnitPrice <= 0 {
			return nil, ErrInvalidPrice
		}
		if it.Currency != currency {
			return nil, ErrCurrencyMismatch
		}
		total += int64(it.Quantity) * it.UnitPrice
	}

	now := time.Now().UTC()
	return &Order{
		ID:              uuid.New(),
		CustomerID:      in.CustomerID,
		Status:          StatusPending,
		Items:           in.Items,
		TotalPrice:      total,
		Currency:        currency,
		PaymentMethod:   in.PaymentMethod,
		Contact:         in.Contact,
		ShippingAddress: in.ShippingAddress,
		IdempotencyKey:  in.IdempotencyKey,
		Version:         1,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// CanTransitionTo reports whether the order may move to the target status.
func (o *Order) CanTransitionTo(target Status) bool {
	next, ok := allowedTransitions[o.Status]
	if !ok {
		return false
	}
	return next[target]
}

// TransitionTo applies a state change, enforcing the state machine.
func (o *Order) TransitionTo(target Status) error {
	if !target.Valid() {
		return ErrInvalidTransition
	}
	if len(allowedTransitions[o.Status]) == 0 {
		return ErrTransitionFromFinal
	}
	if !o.CanTransitionTo(target) {
		return ErrInvalidTransition
	}
	o.Status = target
	o.Version++
	o.UpdatedAt = time.Now().UTC()
	return nil
}

// IsFinal reports whether the order is in a terminal state.
func (o *Order) IsFinal() bool {
	return len(allowedTransitions[o.Status]) == 0
}
