package ratelimit

import (
	"context"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

// Redis is a distributed token-bucket limiter backed by redis_rate (GCRA).
// It enforces a global per-key quota across all service replicas.
type Redis struct {
	limiter *redis_rate.Limiter
	limit   redis_rate.Limit
}

// NewRedis builds a distributed limiter allowing `rps` requests/sec with the
// given burst, shared across the cluster.
func NewRedis(client *redis.Client, rps int, burst int) *Redis {
	return &Redis{
		limiter: redis_rate.NewLimiter(client),
		limit: redis_rate.Limit{
			Rate:   rps,
			Burst:  burst,
			Period: time.Second,
		},
	}
}

// Allow consumes one token for key.
func (r *Redis) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	res, err := r.limiter.Allow(ctx, "rl:"+key, r.limit)
	if err != nil {
		return false, 0, err
	}
	if res.Allowed > 0 {
		return true, 0, nil
	}
	return false, res.RetryAfter, nil
}

var _ DistributedLimiter = (*Redis)(nil)
