package observability

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// PostgresChecker reports Postgres readiness.
type PostgresChecker struct{ Pool *pgxpool.Pool }

func (c PostgresChecker) Name() string { return "postgres" }
func (c PostgresChecker) Check(ctx context.Context) error {
	return c.Pool.Ping(ctx)
}

// RedisChecker reports Redis readiness.
type RedisChecker struct{ Client *redis.Client }

func (c RedisChecker) Name() string { return "redis" }
func (c RedisChecker) Check(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}
