// Package idempotency implements safe replay protection for unsafe (mutating)
// HTTP requests via an Idempotency-Key header, backed by Redis.
//
// Guarantees:
//   - The same key + same request body returns the original stored response,
//     never re-executing the side effect (no double charges / double orders).
//   - Concurrent retries of an in-flight request get 409 (still processing)
//     instead of racing, via an atomic SET NX lock.
//   - A different body reused with the same key is rejected (key reuse abuse).
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrInFlight means an identical request is currently being processed.
	ErrInFlight = errors.New("idempotency: request in flight")
	// ErrKeyReuse means the key was used before with a different request body.
	ErrKeyReuse = errors.New("idempotency: key reused with different payload")
)

// Record is a stored, completed response keyed by the idempotency key.
type Record struct {
	Status      int               `json:"status"`
	Body        []byte            `json:"body"`
	Headers     map[string]string `json:"headers"`
	RequestHash string            `json:"request_hash"`
}

// Store persists idempotency records in Redis.
type Store struct {
	client *redis.Client
	ttl    time.Duration
}

// NewStore builds the store. ttl is how long a key is remembered.
func NewStore(client *redis.Client, ttl time.Duration) *Store {
	return &Store{client: client, ttl: ttl}
}

func key(idempKey string) string  { return "idem:" + idempKey }
func lockKey(idempKey string) string { return "idem:lock:" + idempKey }

// HashRequest returns a stable digest binding the key to a specific request.
func HashRequest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Begin attempts to start processing for idempKey.
//
// Returns:
//   - (record, true, nil)  : a completed response exists; replay it.
//   - (nil, false, nil)    : caller acquired the lock; proceed to execute then
//     call Complete (or Abort on failure).
//   - (nil, false, ErrInFlight) : another worker holds the lock.
//   - (nil, false, ErrKeyReuse) : key seen with a different request hash.
func (s *Store) Begin(ctx context.Context, idempKey, requestHash string) (*Record, bool, error) {
	// 1. Fast path: a completed record already exists.
	if rec, ok, err := s.get(ctx, idempKey); err != nil {
		return nil, false, err
	} else if ok {
		if rec.RequestHash != requestHash {
			return nil, false, ErrKeyReuse
		}
		return rec, true, nil
	}

	// 2. Try to acquire an in-flight lock atomically.
	ok, err := s.client.SetNX(ctx, lockKey(idempKey), requestHash, s.ttl).Result()
	if err != nil {
		return nil, false, fmt.Errorf("acquire lock: %w", err)
	}
	if !ok {
		// Either still processing, or completed between step 1 and 2.
		if rec, found, gErr := s.get(ctx, idempKey); gErr == nil && found {
			if rec.RequestHash != requestHash {
				return nil, false, ErrKeyReuse
			}
			return rec, true, nil
		}
		return nil, false, ErrInFlight
	}
	return nil, false, nil
}

// Complete stores the final response and releases the lock.
func (s *Store) Complete(ctx context.Context, idempKey string, rec Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, key(idempKey), data, s.ttl)
	pipe.Del(ctx, lockKey(idempKey))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store record: %w", err)
	}
	return nil
}

// Abort releases the in-flight lock without storing a result (e.g. on 5xx), so
// the client may safely retry.
func (s *Store) Abort(ctx context.Context, idempKey string) error {
	return s.client.Del(ctx, lockKey(idempKey)).Err()
}

func (s *Store) get(ctx context.Context, idempKey string) (*Record, bool, error) {
	data, err := s.client.Get(ctx, key(idempKey)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get record: %w", err)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false, fmt.Errorf("unmarshal record: %w", err)
	}
	return &rec, true, nil
}
