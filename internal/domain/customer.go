package domain

import (
	"log/slog"
	"strings"

	"github.com/RastBast/ordermesh-/internal/security/pii"
)

// ContactInfo holds customer PII attached to an order. It is encrypted at rest
// (see the repository) and implements slog.LogValuer so that even an accidental
// `slog.Any("contact", c)` emits masked values, never plaintext.
type ContactInfo struct {
	FullName string
	Email    string
	Phone    string
}

// Validate performs lightweight structural checks (full validation belongs to
// the edge / a dedicated validator).
func (c ContactInfo) Validate() error {
	if strings.TrimSpace(c.FullName) == "" {
		return ErrInvalidContact
	}
	if !strings.Contains(c.Email, "@") {
		return ErrInvalidContact
	}
	return nil
}

// LogValue implements slog.LogValuer — masks all PII in logs/traces.
func (c ContactInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", pii.MaskName(c.FullName)),
		slog.String("email", pii.MaskEmail(c.Email)),
		slog.String("phone", pii.MaskPhone(c.Phone)),
	)
}

// ShippingAddress holds delivery PII. Also masked for observability.
type ShippingAddress struct {
	Line1      string
	Line2      string
	City       string
	PostalCode string
	Country    string // ISO-3166 alpha-2
}

// Validate checks required address fields.
func (a ShippingAddress) Validate() error {
	if strings.TrimSpace(a.Line1) == "" ||
		strings.TrimSpace(a.City) == "" ||
		strings.TrimSpace(a.PostalCode) == "" ||
		len(a.Country) != 2 {
		return ErrInvalidAddress
	}
	return nil
}

// LogValue masks street-level detail, keeping only city/country for debugging.
func (a ShippingAddress) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("line1", "[REDACTED]"),
		slog.String("city", a.City),
		slog.String("country", a.Country),
	)
}
