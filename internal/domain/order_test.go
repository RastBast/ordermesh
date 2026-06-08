package domain

import (
	"testing"

	"github.com/google/uuid"
)

func validItems() []Item {
	return []Item{
		{SKU: "SKU-1", Name: "Widget", Quantity: 2, UnitPrice: 1500, Currency: "USD"},
		{SKU: "SKU-2", Name: "Gadget", Quantity: 1, UnitPrice: 3000, Currency: "USD"},
	}
}

func validContact() ContactInfo {
	return ContactInfo{FullName: "Ada Lovelace", Email: "ada@example.com", Phone: "+1 415 555 1234"}
}

func validAddress() ShippingAddress {
	return ShippingAddress{Line1: "1 Main St", City: "London", PostalCode: "EC1", Country: "GB"}
}

func validInput(customerID uuid.UUID, items []Item) NewOrderInput {
	return NewOrderInput{
		CustomerID:      customerID,
		Items:           items,
		PaymentMethod:   PaymentCard,
		Contact:         validContact(),
		ShippingAddress: validAddress(),
		IdempotencyKey:  "idem-1",
	}
}

func TestNewOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		customerID uuid.UUID
		items      []Item
		wantErr    error
		wantTotal  int64
	}{
		{
			name:       "valid order computes total",
			customerID: uuid.New(),
			items:      validItems(),
			wantTotal:  2*1500 + 3000,
		},
		{
			name:       "empty customer",
			customerID: uuid.Nil,
			items:      validItems(),
			wantErr:    ErrInvalidCustomer,
		},
		{
			name:       "no items",
			customerID: uuid.New(),
			items:      nil,
			wantErr:    ErrEmptyItems,
		},
		{
			name:       "zero quantity",
			customerID: uuid.New(),
			items:      []Item{{SKU: "x", Quantity: 0, UnitPrice: 100, Currency: "USD"}},
			wantErr:    ErrInvalidQuantity,
		},
		{
			name:       "negative price",
			customerID: uuid.New(),
			items:      []Item{{SKU: "x", Quantity: 1, UnitPrice: -5, Currency: "USD"}},
			wantErr:    ErrInvalidPrice,
		},
		{
			name:       "currency mismatch",
			customerID: uuid.New(),
			items: []Item{
				{SKU: "a", Quantity: 1, UnitPrice: 100, Currency: "USD"},
				{SKU: "b", Quantity: 1, UnitPrice: 100, Currency: "EUR"},
			},
			wantErr: ErrCurrencyMismatch,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o, err := NewOrder(validInput(tt.customerID, tt.items))
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if o.TotalPrice != tt.wantTotal {
				t.Fatalf("want total %d, got %d", tt.wantTotal, o.TotalPrice)
			}
			if o.Status != StatusPending {
				t.Fatalf("want status PENDING, got %s", o.Status)
			}
			if o.Version != 1 {
				t.Fatalf("want version 1, got %d", o.Version)
			}
		})
	}
}

func TestOrderTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		from    Status
		to      Status
		wantErr error
	}{
		{"pending->paid", StatusPending, StatusPaid, nil},
		{"pending->cancelled", StatusPending, StatusCancelled, nil},
		{"paid->shipped", StatusPaid, StatusShipped, nil},
		{"paid->cancelled", StatusPaid, StatusCancelled, nil},
		{"pending->shipped invalid", StatusPending, StatusShipped, ErrInvalidTransition},
		{"shipped is final", StatusShipped, StatusCancelled, ErrTransitionFromFinal},
		{"cancelled is final", StatusCancelled, StatusPaid, ErrTransitionFromFinal},
		{"unknown target", StatusPending, Status("WAT"), ErrInvalidTransition},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := &Order{Status: tt.from, Version: 1}
			err := o.TransitionTo(tt.to)
			if err != tt.wantErr {
				t.Fatalf("want err %v, got %v", tt.wantErr, err)
			}
			if tt.wantErr == nil {
				if o.Status != tt.to {
					t.Fatalf("want status %s, got %s", tt.to, o.Status)
				}
				if o.Version != 2 {
					t.Fatalf("want version bumped to 2, got %d", o.Version)
				}
			}
		})
	}
}
