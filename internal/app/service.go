// Package app contains the application services (use cases). It orchestrates
// the domain, repositories, cache and outbox. It knows nothing about HTTP,
// SQL dialects or Kafka wire formats — only the ports.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// Service is the order use-case orchestrator.
type Service struct {
	uow   ports.UnitOfWork
	cache ports.Cache
	log   *slog.Logger
}

// NewService wires the application service.
func NewService(uow ports.UnitOfWork, cache ports.Cache, log *slog.Logger) *Service {
	return &Service{uow: uow, cache: cache, log: log}
}

// CreateOrderItem is the input DTO for a line item.
type CreateOrderItem struct {
	SKU       string
	Name      string
	Quantity  int32
	UnitPrice int64
	Currency  string
}

// CreateOrderInput is the input DTO for creating an order.
type CreateOrderInput struct {
	CustomerID      uuid.UUID
	Items           []CreateOrderItem
	PaymentMethod   string
	Contact         domain.ContactInfo
	ShippingAddress domain.ShippingAddress
	IdempotencyKey  string
}

// orderCreatedPayload is the JSON published on order.created.
type orderCreatedPayload struct {
	OrderID    uuid.UUID `json:"order_id"`
	CustomerID uuid.UUID `json:"customer_id"`
	TotalPrice int64     `json:"total_price"`
	Currency   string    `json:"currency"`
	Status     string    `json:"status"`
}

// statusChangedPayload is published on order.paid / shipped / cancelled.
type statusChangedPayload struct {
	OrderID uuid.UUID `json:"order_id"`
	Status  string    `json:"status"`
	Version int64     `json:"version"`
}

// CreateOrder validates input, persists the aggregate and its order.created
// event atomically (outbox), then warms the cache.
func (s *Service) CreateOrder(ctx context.Context, in CreateOrderInput) (*domain.Order, error) {
	items := make([]domain.Item, 0, len(in.Items))
	for _, it := range in.Items {
		items = append(items, domain.Item{
			SKU:       it.SKU,
			Name:      it.Name,
			Quantity:  it.Quantity,
			UnitPrice: it.UnitPrice,
			Currency:  it.Currency,
		})
	}

	order, err := domain.NewOrder(domain.NewOrderInput{
		CustomerID:      in.CustomerID,
		Items:           items,
		PaymentMethod:   domain.PaymentMethod(in.PaymentMethod),
		Contact:         in.Contact,
		ShippingAddress: in.ShippingAddress,
		IdempotencyKey:  in.IdempotencyKey,
	})
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(orderCreatedPayload{
		OrderID:    order.ID,
		CustomerID: order.CustomerID,
		TotalPrice: order.TotalPrice,
		Currency:   order.Currency,
		Status:     string(order.Status),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal event payload: %w", err)
	}
	event := domain.NewEvent(domain.EventOrderCreated, order.ID, payload)

	err = s.uow.Do(ctx, func(ctx context.Context, repo ports.Repository, outbox ports.Outbox) error {
		if err := repo.Create(ctx, order); err != nil {
			return err
		}
		return outbox.Add(ctx, event)
	})
	if err != nil {
		return nil, err
	}

	if err := s.cache.SetOrder(ctx, order); err != nil {
		s.log.WarnContext(ctx, "cache set failed", slog.String("order_id", order.ID.String()), slog.Any("err", err))
	}
	return order, nil
}

// GetOrder reads through the cache, falling back to the repository.
func (s *Service) GetOrder(ctx context.Context, id uuid.UUID) (*domain.Order, error) {
	if o, ok, err := s.cache.GetOrder(ctx, id); err != nil {
		s.log.WarnContext(ctx, "cache get failed", slog.Any("err", err))
	} else if ok {
		return o, nil
	}

	var order *domain.Order
	err := s.uow.Do(ctx, func(ctx context.Context, repo ports.Repository, _ ports.Outbox) error {
		o, err := repo.GetByID(ctx, id)
		if err != nil {
			return err
		}
		order = o
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := s.cache.SetOrder(ctx, order); err != nil {
		s.log.WarnContext(ctx, "cache set failed", slog.Any("err", err))
	}
	return order, nil
}

// ListOrders returns a filtered page of orders (no caching).
func (s *Service) ListOrders(ctx context.Context, f ports.ListFilter) ([]*domain.Order, error) {
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	var out []*domain.Order
	err := s.uow.Do(ctx, func(ctx context.Context, repo ports.Repository, _ ports.Outbox) error {
		list, err := repo.List(ctx, f)
		if err != nil {
			return err
		}
		out = list
		return nil
	})
	return out, err
}

// ChangeStatus applies a state-machine transition atomically with an outbox
// event, using optimistic locking, then invalidates the cache.
func (s *Service) ChangeStatus(ctx context.Context, id uuid.UUID, target domain.Status) (*domain.Order, error) {
	if !target.Valid() {
		return nil, domain.ErrInvalidTransition
	}

	var updated *domain.Order
	err := s.uow.Do(ctx, func(ctx context.Context, repo ports.Repository, outbox ports.Outbox) error {
		order, err := repo.GetByID(ctx, id)
		if err != nil {
			return err
		}
		expected := order.Version
		if err := order.TransitionTo(target); err != nil {
			return err
		}

		payload, err := json.Marshal(statusChangedPayload{
			OrderID: order.ID,
			Status:  string(order.Status),
			Version: order.Version,
		})
		if err != nil {
			return fmt.Errorf("marshal event payload: %w", err)
		}
		event := domain.NewEvent(domain.EventForStatus(order.Status), order.ID, payload)

		if err := repo.Update(ctx, order, expected); err != nil {
			return err
		}
		if err := outbox.Add(ctx, event); err != nil {
			return err
		}
		updated = order
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := s.cache.DeleteOrder(ctx, id); err != nil {
		s.log.WarnContext(ctx, "cache delete failed", slog.Any("err", err))
	}
	return updated, nil
}

// IsConflict reports whether an error should map to HTTP 409.
func IsConflict(err error) bool {
	return errors.Is(err, domain.ErrOptimisticLock) || errors.Is(err, domain.ErrOrderAlreadyExists)
}
