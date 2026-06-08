// Command order-service is the entrypoint for the Order microservice.
//
// It wires configuration, observability, Postgres, Redis and Kafka, starts the
// HTTP API and the transactional-outbox relay, and shuts everything down
// gracefully on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/RastBast/ordermesh-/internal/adapters/broker/kafkabroker"
	"github.com/RastBast/ordermesh-/internal/adapters/cache/redisrepo"
	"github.com/RastBast/ordermesh-/internal/adapters/httpapi"
	pgrepo "github.com/RastBast/ordermesh-/internal/adapters/repository/postgres"
	"github.com/RastBast/ordermesh-/internal/app"
	"github.com/RastBast/ordermesh-/internal/config"
	kafkaplatform "github.com/RastBast/ordermesh-/internal/platform/kafka"
	"github.com/RastBast/ordermesh-/internal/platform/logger"
	"github.com/RastBast/ordermesh-/internal/platform/observability"
	pgplatform "github.com/RastBast/ordermesh-/internal/platform/postgres"
	redisplatform "github.com/RastBast/ordermesh-/internal/platform/redis"
	httpserver "github.com/RastBast/ordermesh-/internal/platform/httpserver"
	"github.com/RastBast/ordermesh-/internal/security/auth"
	"github.com/RastBast/ordermesh-/internal/security/crypto"
	"github.com/RastBast/ordermesh-/internal/security/idempotency"
	"github.com/RastBast/ordermesh-/internal/security/ratelimit"
)

func main() {
	if err := run(); err != nil {
		// logger may not be ready; use stderr as last resort.
		println("fatal:", err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := logger.New(cfg.LogLevel, cfg.Env)
	log.Info("starting order-service", "env", cfg.Env)

	// Root context cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Observability ---
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	metrics := observability.NewMetrics(reg)

	shutdownTracer, err := observability.InitTracer(ctx, cfg.Observability.ServiceName, cfg.Observability.OTLPEndpoint, cfg.Observability.TraceSampleRatio)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracer(shutdownCtx)
	}()

	// --- Infrastructure ---
	pool, err := pgplatform.New(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to postgres")

	redisClient, err := redisplatform.New(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	defer func() { _ = redisClient.Close() }()
	log.Info("connected to redis")

	kafkaWriter, err := kafkaplatform.NewWriter(cfg.Kafka)
	if err != nil {
		return err
	}
	publisher := kafkabroker.New(kafkaWriter)
	defer func() { _ = publisher.Close() }()
	log.Info("kafka writer ready", "topic", cfg.Kafka.Topic, "tls", cfg.Kafka.TLSEnabled, "sasl", cfg.Kafka.SASLEnabled)

	// --- Security primitives ---
	keyring, err := crypto.LoadKeyring(cfg.Security.EncryptionKeys)
	if err != nil {
		return err
	}
	log.Info("pii encryption keyring loaded", "keys", len(cfg.Security.EncryptionKeys))

	var verifier httpapi.TokenVerifier
	if cfg.Security.AuthEnabled {
		jwks := auth.NewJWKSClient(cfg.Security.JWKSURL)
		v := auth.NewVerifier(jwks, auth.Config{
			JWKSURL:  cfg.Security.JWKSURL,
			Issuer:   cfg.Security.JWTIssuer,
			Audience: cfg.Security.JWTAudience,
		})
		// Fail fast if the IdP / JWKS is unreachable at boot.
		if err := v.WarmUp(ctx); err != nil {
			return fmt.Errorf("jwks warmup: %w", err)
		}
		verifier = v
		log.Info("jwt verification enabled", "issuer", cfg.Security.JWTIssuer)
	} else {
		log.Warn("AUTH DISABLED — dev mode only")
	}

	idemStore := idempotency.NewStore(redisClient, cfg.Security.IdempotencyTTL)
	localRL := ratelimit.NewLocal(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst)
	defer localRL.Close()
	distRL := ratelimit.NewRedis(redisClient, int(cfg.Security.RateLimitRPS), cfg.Security.RateLimitBurst)

	// --- Adapters & application wiring ---
	uow := pgrepo.NewUnitOfWork(pool, keyring)
	outboxStore := pgrepo.NewOutboxStore(pool)
	cache := redisrepo.New(redisClient, cfg.Redis.TTL,
		redisrepo.WithMetricsHooks(metrics.CacheHits.Inc, metrics.CacheMisses.Inc),
	)
	service := app.NewService(uow, cache, log)

	relay := app.NewRelay(outboxStore, publisher, log, cfg.Outbox.PollInterval, cfg.Outbox.BatchSize,
		app.WithPublishedHook(func(eventType string) {
			metrics.EventsPublished.WithLabelValues(eventType).Inc()
		}),
	)

	// --- HTTP API ---
	handler := httpapi.NewHandler(service, log)
	router := httpapi.NewRouter(httpapi.RouterDeps{
		Handler: handler,
		Metrics: metrics,
		Log:     log,
		Readiness: []httpapi.HealthChecker{
			observability.PostgresChecker{Pool: pool},
			observability.RedisChecker{Client: redisClient},
		},
		Verifier:         verifier,
		Idempotency:      idemStore,
		LocalRateLimiter: localRL,
		DistRateLimiter:  distRL,
		DevMode:          !cfg.Security.AuthEnabled,
	})
	apiServer := httpserver.New(cfg.HTTP, router, log)

	// --- Metrics server (separate port) ---
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsSrv := &http.Server{Addr: cfg.Observability.MetricsAddr, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}

	// --- Run everything concurrently; first error cancels the group ---
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return apiServer.Start(gctx) })

	g.Go(func() error {
		log.Info("metrics server listening", "addr", cfg.Observability.MetricsAddr)
		errCh := make(chan error, 1)
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		select {
		case <-gctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return metricsSrv.Shutdown(shutdownCtx)
		case err := <-errCh:
			return err
		}
	})

	g.Go(func() error {
		err := relay.Run(gctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})

	// Periodically export the outbox backlog gauge.
	g.Go(func() error {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-ticker.C:
				if n, err := outboxStore.CountPending(gctx); err == nil {
					metrics.OutboxPending.Set(float64(n))
				}
			}
		}
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("service stopped with error", "err", err)
		return err
	}
	log.Info("service stopped cleanly")
	return nil
}
