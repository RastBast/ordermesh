package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// Repository implements ports.Repository against a pgx querier (tx).
type Repository struct {
	q   querier
	enc Encryptor
}

// contactBlob is the JSON structure encrypted at rest for contact PII.
type contactBlob struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

// addressBlob is the JSON structure encrypted at rest for the shipping address.
type addressBlob struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2"`
	City       string `json:"city"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

// encryptPII serialises and seals the order's PII, bound to the order id (AAD).
func (r *Repository) encryptPII(o *domain.Order) (contactEnc, addressEnc string, err error) {
	aad := o.ID.String()

	cb, err := json.Marshal(contactBlob{
		FullName: o.Contact.FullName, Email: o.Contact.Email, Phone: o.Contact.Phone,
	})
	if err != nil {
		return "", "", fmt.Errorf("marshal contact: %w", err)
	}
	contactEnc, err = r.enc.EncryptString(string(cb), aad)
	if err != nil {
		return "", "", fmt.Errorf("encrypt contact: %w", err)
	}

	ab, err := json.Marshal(addressBlob{
		Line1: o.ShippingAddress.Line1, Line2: o.ShippingAddress.Line2,
		City: o.ShippingAddress.City, PostalCode: o.ShippingAddress.PostalCode, Country: o.ShippingAddress.Country,
	})
	if err != nil {
		return "", "", fmt.Errorf("marshal address: %w", err)
	}
	addressEnc, err = r.enc.EncryptString(string(ab), aad)
	if err != nil {
		return "", "", fmt.Errorf("encrypt address: %w", err)
	}
	return contactEnc, addressEnc, nil
}

// decryptPII opens the sealed PII into the order (city/country left in
// plaintext columns for filtering remain authoritative on the address blob).
func (r *Repository) decryptPII(o *domain.Order, contactEnc, addressEnc string) error {
	aad := o.ID.String()

	if contactEnc != "" {
		cb, err := r.enc.DecryptString(contactEnc, aad)
		if err != nil {
			return fmt.Errorf("decrypt contact: %w", err)
		}
		var c contactBlob
		if err := json.Unmarshal([]byte(cb), &c); err != nil {
			return fmt.Errorf("unmarshal contact: %w", err)
		}
		o.Contact = domain.ContactInfo{FullName: c.FullName, Email: c.Email, Phone: c.Phone}
	}

	if addressEnc != "" {
		ab, err := r.enc.DecryptString(addressEnc, aad)
		if err != nil {
			return fmt.Errorf("decrypt address: %w", err)
		}
		var a addressBlob
		if err := json.Unmarshal([]byte(ab), &a); err != nil {
			return fmt.Errorf("unmarshal address: %w", err)
		}
		o.ShippingAddress = domain.ShippingAddress{
			Line1: a.Line1, Line2: a.Line2, City: a.City, PostalCode: a.PostalCode, Country: a.Country,
		}
	}
	return nil
}

// itemRow is the JSONB shape for an order item.
type itemRow struct {
	SKU       string `json:"sku"`
	Name      string `json:"name"`
	Quantity  int32  `json:"quantity"`
	UnitPrice int64  `json:"unit_price"`
	Currency  string `json:"currency"`
}

func toItemRows(items []domain.Item) []itemRow {
	out := make([]itemRow, 0, len(items))
	for _, it := range items {
		out = append(out, itemRow{
			SKU: it.SKU, Name: it.Name, Quantity: it.Quantity,
			UnitPrice: it.UnitPrice, Currency: it.Currency,
		})
	}
	return out
}

func fromItemRows(rows []itemRow) []domain.Item {
	out := make([]domain.Item, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Item{
			SKU: r.SKU, Name: r.Name, Quantity: r.Quantity,
			UnitPrice: r.UnitPrice, Currency: r.Currency,
		})
	}
	return out
}

// Create inserts a new order, encrypting PII at rest.
func (r *Repository) Create(ctx context.Context, o *domain.Order) error {
	itemsJSON, err := json.Marshal(toItemRows(o.Items))
	if err != nil {
		return fmt.Errorf("marshal items: %w", err)
	}
	contactEnc, addressEnc, err := r.encryptPII(o)
	if err != nil {
		return err
	}

	const q = `
		INSERT INTO orders (
			id, customer_id, status, items, total_price, currency, payment_method,
			contact_enc, shipping_address_enc, ship_city, ship_country,
			idempotency_key, version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	_, err = r.q.Exec(ctx, q,
		o.ID, o.CustomerID, o.Status, itemsJSON, o.TotalPrice, o.Currency, o.PaymentMethod,
		contactEnc, addressEnc, o.ShippingAddress.City, o.ShippingAddress.Country,
		nullIfEmpty(o.IdempotencyKey), o.Version, o.CreatedAt, o.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrOrderAlreadyExists
		}
		return fmt.Errorf("insert order: %w", err)
	}
	return nil
}

// GetByID loads an order by id and decrypts its PII.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Order, error) {
	const q = `
		SELECT id, customer_id, status, items, total_price, currency, payment_method,
		       contact_enc, shipping_address_enc, version, created_at, updated_at
		FROM orders WHERE id = $1`
	return r.scanOrder(r.q.QueryRow(ctx, q, id))
}

// Update applies an optimistic-locked update, re-encrypting PII.
func (r *Repository) Update(ctx context.Context, o *domain.Order, expectedVersion int64) error {
	itemsJSON, err := json.Marshal(toItemRows(o.Items))
	if err != nil {
		return fmt.Errorf("marshal items: %w", err)
	}
	contactEnc, addressEnc, err := r.encryptPII(o)
	if err != nil {
		return err
	}

	const q = `
		UPDATE orders
		SET status=$1, items=$2, total_price=$3, currency=$4, payment_method=$5,
		    contact_enc=$6, shipping_address_enc=$7, ship_city=$8, ship_country=$9,
		    version=$10, updated_at=$11
		WHERE id=$12 AND version=$13`
	tag, err := r.q.Exec(ctx, q,
		o.Status, itemsJSON, o.TotalPrice, o.Currency, o.PaymentMethod,
		contactEnc, addressEnc, o.ShippingAddress.City, o.ShippingAddress.Country,
		o.Version, o.UpdatedAt, o.ID, expectedVersion,
	)
	if err != nil {
		return fmt.Errorf("update order: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrOptimisticLock
	}
	return nil
}

// List returns filtered orders with decrypted PII.
func (r *Repository) List(ctx context.Context, f ports.ListFilter) ([]*domain.Order, error) {
	q := `
		SELECT id, customer_id, status, items, total_price, currency, payment_method,
		       contact_enc, shipping_address_enc, version, created_at, updated_at
		FROM orders WHERE 1=1`
	args := make([]any, 0, 4)
	i := 1
	if f.CustomerID != nil {
		q += fmt.Sprintf(" AND customer_id = $%d", i)
		args = append(args, *f.CustomerID)
		i++
	}
	if f.Status != nil {
		q += fmt.Sprintf(" AND status = $%d", i)
		args = append(args, *f.Status)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", i, i+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := r.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query orders: %w", err)
	}
	defer rows.Close()

	var out []*domain.Order
	for rows.Next() {
		o, err := r.scanOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate orders: %w", err)
	}
	return out, nil
}

// scanRow is satisfied by both pgx.Row and pgx.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

func (r *Repository) scanOrder(row scanRow) (*domain.Order, error) {
	var (
		o          domain.Order
		itemsJSON  []byte
		contactEnc string
		addressEnc string
	)
	err := row.Scan(
		&o.ID, &o.CustomerID, &o.Status, &itemsJSON, &o.TotalPrice, &o.Currency, &o.PaymentMethod,
		&contactEnc, &addressEnc, &o.Version, &o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrderNotFound
		}
		return nil, fmt.Errorf("scan order: %w", err)
	}
	var rows []itemRow
	if err := json.Unmarshal(itemsJSON, &rows); err != nil {
		return nil, fmt.Errorf("unmarshal items: %w", err)
	}
	o.Items = fromItemRows(rows)
	if err := r.decryptPII(&o, contactEnc, addressEnc); err != nil {
		return nil, err
	}
	return &o, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
