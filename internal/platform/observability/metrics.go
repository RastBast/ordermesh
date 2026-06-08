// Package observability wires Prometheus metrics and an OpenTelemetry tracer.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds the application's Prometheus collectors.
type Metrics struct {
	HTTPRequests   *prometheus.CounterVec
	HTTPDuration   *prometheus.HistogramVec
	OutboxPending  prometheus.Gauge
	EventsPublished *prometheus.CounterVec
	CacheHits      prometheus.Counter
	CacheMisses    prometheus.Counter
}

// NewMetrics registers and returns the collectors on the given registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		HTTPRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, route and status.",
		}, []string{"method", "route", "status"}),
		HTTPDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		OutboxPending: factory.NewGauge(prometheus.GaugeOpts{
			Name: "outbox_pending_events",
			Help: "Number of unpublished events in the outbox.",
		}),
		EventsPublished: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "events_published_total",
			Help: "Total events published to the broker by type.",
		}, []string{"type"}),
		CacheHits: factory.NewCounter(prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total cache hits.",
		}),
		CacheMisses: factory.NewCounter(prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total cache misses.",
		}),
	}
}
