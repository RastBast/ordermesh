// Package redisrepo implements ports.Cache on top of go-redis.
package redisrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// Cache is a JSON serialising read-through cache for orders.
type Cache struct {
	client *redis.Client
	ttl    time.Duration

	onHit  func()
	onMiss func()
}

// Option customises the cache.
type Option func(*Cache)

// WithMetricsHooks registers hit/miss callbacks.
func WithMetricsHooks(onHit, onMiss func()) Option {
	return func(c *Cache) {
		c.onHit = onHit
		c.onMiss = onMiss
	}
}

// New constructs the Redis cache adapter.
func New(client *redis.Client, ttl time.Duration, opts ...Option) *Cache {
	c := &Cache{client: client, ttl: ttl, onHit: func() {}, onMiss: func() {}}
	for _, o := range opts {
		o(c)
	}
	return c
}

func key(id uuid.UUID) string { return "order:" + id.String() }

// GetOrder returns the cached order if present.
func (c *Cache) GetOrder(ctx context.Context, id uuid.UUID) (*domain.Order, bool, error) {
	data, err := c.client.Get(ctx, key(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.onMiss()
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("redis get: %w", err)
	}
	var o domain.Order
	if err := json.Unmarshal(data, &o); err != nil {
		// Treat corrupt cache entries as a miss rather than failing the read.
		c.onMiss()
		return nil, false, nil
	}
	c.onHit()
	return &o, true, nil
}

// SetOrder stores the order with the configured TTL.
func (c *Cache) SetOrder(ctx context.Context, o *domain.Order) error {
	data, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshal order: %w", err)
	}
	if err := c.client.Set(ctx, key(o.ID), data, c.ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// DeleteOrder removes the cached order.
func (c *Cache) DeleteOrder(ctx context.Context, id uuid.UUID) error {
	if err := c.client.Del(ctx, key(id)).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}

var _ ports.Cache = (*Cache)(nil)
