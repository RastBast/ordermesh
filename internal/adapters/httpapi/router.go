package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/RastBast/ordermesh-/internal/platform/observability"
	"github.com/RastBast/ordermesh-/internal/security/auth"
	"github.com/RastBast/ordermesh-/internal/security/ratelimit"
)

// HealthChecker reports liveness/readiness of a dependency.
type HealthChecker interface {
	// Check returns nil when healthy.
	Check(ctx context.Context) error
	Name() string
}

// RouterDeps bundles router dependencies.
type RouterDeps struct {
	Handler   *Handler
	Metrics   *observability.Metrics
	Log       *slog.Logger
	Readiness []HealthChecker

	// Security dependencies. When Verifier is nil, auth middleware is skipped
	// (used in unit tests). In production all must be set.
	Verifier         TokenVerifier
	Idempotency      IdempotencyStore
	LocalRateLimiter *ratelimit.Local
	DistRateLimiter  ratelimit.DistributedLimiter

	// DevMode injects a full-permission principal when Verifier is nil
	// (AUTH_ENABLED=false). Set only by the prod wiring; unit tests leave it
	// false so they exercise raw handler authorization logic.
	DevMode bool
}

// NewRouter builds the chi router with the full middleware stack.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()

	// Baseline middleware (applies to everything).
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(RecovererMiddleware(deps.Log))
	r.Use(LoggingMiddleware(deps.Log))
	r.Use(MetricsMiddleware(deps.Metrics))
	r.Use(SecurityHeadersMiddleware)
	r.Use(middleware.Timeout(30 * time.Second))

	// Liveness: process is up. Unauthenticated by design.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Readiness: dependencies are reachable. Unauthenticated by design.
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		results := make(map[string]string, len(deps.Readiness))
		ready := true
		for _, c := range deps.Readiness {
			if err := c.Check(ctx); err != nil {
				ready = false
				results[c.Name()] = "down: " + err.Error()
			} else {
				results[c.Name()] = "ok"
			}
		}
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{"ready": ready, "checks": results})
	})

	// Authenticated, rate-limited API surface.
	r.Group(func(r chi.Router) {
		if deps.Verifier != nil {
			r.Use(AuthMiddleware(deps.Verifier, deps.Log))
		} else if deps.DevMode {
			// Dev mode (AUTH_ENABLED=false): inject a full-permission principal
			// so handlers operate normally. NEVER reached in prod — config
			// validation forbids AUTH_ENABLED=false when APP_ENV=prod.
			r.Use(DevAuthMiddleware(deps.Log))
		}
		if deps.LocalRateLimiter != nil {
			r.Use(PerPrincipalRateLimit(deps.LocalRateLimiter, deps.DistRateLimiter, deps.Log))
		}

		r.Route("/v1/orders", func(r chi.Router) {
			// POST: create — RBAC orders.create + idempotency guard.
			r.Group(func(r chi.Router) {
				if deps.Verifier != nil {
					r.Use(RequirePermission(auth.PermOrdersCreate))
				}
				if deps.Idempotency != nil {
					r.Use(IdempotencyMiddleware(deps.Idempotency, deps.Log))
				}
				r.Post("/", deps.Handler.CreateOrder)
			})

			// GET list — needs read.own or list.any (fine-grained inside handler).
			r.With(requireIf(deps.Verifier, auth.PermOrdersReadOwn, auth.PermOrdersListAny)).
				Get("/", deps.Handler.ListOrders)

			// GET one — read.own or read.any.
			r.With(requireIf(deps.Verifier, auth.PermOrdersReadOwn, auth.PermOrdersReadAny)).
				Get("/{id}", deps.Handler.GetOrder)

			// PATCH status — update.own or update.any.
			r.With(requireIf(deps.Verifier, auth.PermOrdersUpdateOwn, auth.PermOrdersUpdateAny)).
				Patch("/{id}/status", deps.Handler.ChangeStatus)
		})
	})

	return r
}

// requireIf returns the RequirePermission middleware only when auth is enabled,
// otherwise a pass-through (keeps unit tests free of auth wiring).
func requireIf(v TokenVerifier, perms ...auth.Permission) func(http.Handler) http.Handler {
	if v == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return RequirePermission(perms...)
}
