package httpapi

import (
	"time"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/security/pii"
)

// createOrderRequest is the JSON body for POST /v1/orders.
type createOrderRequest struct {
	CustomerID      string                 `json:"customer_id"`
	Items           []orderItemRequest     `json:"items"`
	PaymentMethod   string                 `json:"payment_method"`
	Contact         contactRequest         `json:"contact"`
	ShippingAddress shippingAddressRequest `json:"shipping_address"`
}

type contactRequest struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type shippingAddressRequest struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2"`
	City       string `json:"city"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type orderItemRequest struct {
	SKU       string `json:"sku"`
	Name      string `json:"name"`
	Quantity  int32  `json:"quantity"`
	UnitPrice int64  `json:"unit_price"`
	Currency  string `json:"currency"`
}

// changeStatusRequest is the JSON body for PATCH /v1/orders/{id}/status.
type changeStatusRequest struct {
	Status string `json:"status"`
}

// orderResponse is the JSON representation of an order. PII is masked by
// default; full PII is exposed only to principals with elevated permissions
// (see Handler.toOrderResponseFor).
type orderResponse struct {
	ID              uuid.UUID           `json:"id"`
	CustomerID      uuid.UUID           `json:"customer_id"`
	Status          string              `json:"status"`
	Items           []orderItemResponse `json:"items"`
	TotalPrice      int64               `json:"total_price"`
	Currency        string              `json:"currency"`
	PaymentMethod   string              `json:"payment_method"`
	Contact         contactResponse     `json:"contact"`
	ShippingAddress shippingResponse    `json:"shipping_address"`
	Version         int64               `json:"version"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

type contactResponse struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type shippingResponse struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type orderItemResponse struct {
	SKU       string `json:"sku"`
	Name      string `json:"name"`
	Quantity  int32  `json:"quantity"`
	UnitPrice int64  `json:"unit_price"`
	Currency  string `json:"currency"`
}

// toOrderResponse renders an order. When unmask is false, PII fields are
// masked (default for least-privilege responses). Only callers with elevated
// permissions (e.g. orders.read.any) should pass unmask=true.
func toOrderResponse(o *domain.Order, unmask bool) orderResponse {
	items := make([]orderItemResponse, 0, len(o.Items))
	for _, it := range o.Items {
		items = append(items, orderItemResponse{
			SKU: it.SKU, Name: it.Name, Quantity: it.Quantity,
			UnitPrice: it.UnitPrice, Currency: it.Currency,
		})
	}

	var contact contactResponse
	var shipping shippingResponse
	if unmask {
		contact = contactResponse{FullName: o.Contact.FullName, Email: o.Contact.Email, Phone: o.Contact.Phone}
		shipping = shippingResponse{
			Line1: o.ShippingAddress.Line1, Line2: o.ShippingAddress.Line2,
			City: o.ShippingAddress.City, PostalCode: o.ShippingAddress.PostalCode, Country: o.ShippingAddress.Country,
		}
	} else {
		contact = contactResponse{
			FullName: pii.MaskName(o.Contact.FullName),
			Email:    pii.MaskEmail(o.Contact.Email),
			Phone:    pii.MaskPhone(o.Contact.Phone),
		}
		shipping = shippingResponse{
			Line1: "[REDACTED]", City: o.ShippingAddress.City, Country: o.ShippingAddress.Country,
		}
	}

	return orderResponse{
		ID:              o.ID,
		CustomerID:      o.CustomerID,
		Status:          string(o.Status),
		Items:           items,
		TotalPrice:      o.TotalPrice,
		Currency:        o.Currency,
		PaymentMethod:   string(o.PaymentMethod),
		Contact:         contact,
		ShippingAddress: shipping,
		Version:         o.Version,
		CreatedAt:       o.CreatedAt,
		UpdatedAt:       o.UpdatedAt,
	}
}

// listResponse wraps a page of orders.
type listResponse struct {
	Items []orderResponse `json:"items"`
	Count int             `json:"count"`
}

// errorResponse is the standard error envelope.
type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
