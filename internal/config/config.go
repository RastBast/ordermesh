// Package config loads strongly-typed configuration from environment
// variables with sane defaults and validation.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the root application configuration.
type Config struct {
	Env      string // dev | staging | prod
	LogLevel string // debug | info | warn | error

	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	Kafka    KafkaConfig
	Outbox   OutboxConfig
	Observability ObservabilityConfig
	Security SecurityConfig
}

// SecurityConfig holds Zero-Trust controls.
type SecurityConfig struct {
	// JWT / JWKS
	JWKSURL      string
	JWTIssuer    string
	JWTAudience  string

	// PII encryption keyring. Keys are base64-encoded 32-byte values, ordered
	// oldest→newest (newest is the active encryption key). Sourced from a
	// secret manager; rotation is a config change.
	EncryptionKeys []string

	// Rate limiting (per principal/IP).
	RateLimitRPS   float64
	RateLimitBurst int

	// Idempotency
	IdempotencyTTL time.Duration

	// AuthEnabled allows disabling auth wiring for local dev only.
	AuthEnabled bool
}

// HTTPConfig holds the HTTP server settings.
type HTTPConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// PostgresConfig holds the database connection settings.
type PostgresConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// RedisConfig holds the cache connection settings.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
	TTL      time.Duration
}

// KafkaConfig holds the broker settings, including SASL/TLS for Zero-Trust
// in-transit security and broker authentication.
type KafkaConfig struct {
	Brokers []string
	Topic   string
	// ClientID identifies this producer to the cluster.
	ClientID string

	// TLS
	TLSEnabled    bool
	TLSServerName string

	// SASL/SCRAM authentication
	SASLEnabled   bool
	SASLMechanism string // PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
	SASLUsername  string
	SASLPassword  string
}

// OutboxConfig configures the background relay.
type OutboxConfig struct {
	PollInterval time.Duration
	BatchSize    int
}

// ObservabilityConfig configures metrics and tracing.
type ObservabilityConfig struct {
	MetricsAddr      string
	OTLPEndpoint     string // empty disables tracing export
	ServiceName      string
	TraceSampleRatio float64
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	cfg := &Config{
		Env:      getEnv("APP_ENV", "dev"),
		LogLevel: getEnv("LOG_LEVEL", "info"),
		HTTP: HTTPConfig{
			Addr:            getEnv("HTTP_ADDR", ":8080"),
			ReadTimeout:     getDuration("HTTP_READ_TIMEOUT", 5*time.Second),
			WriteTimeout:    getDuration("HTTP_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     getDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: getDuration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
		},
		Postgres: PostgresConfig{
			DSN:             getEnv("POSTGRES_DSN", "postgres://order:order@localhost:5432/orders?sslmode=disable"),
			MaxConns:        int32(getInt("POSTGRES_MAX_CONNS", 10)),
			MinConns:        int32(getInt("POSTGRES_MIN_CONNS", 2)),
			MaxConnLifetime: getDuration("POSTGRES_MAX_CONN_LIFETIME", time.Hour),
			MaxConnIdleTime: getDuration("POSTGRES_MAX_CONN_IDLE_TIME", 30*time.Minute),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getInt("REDIS_DB", 0),
			TTL:      getDuration("REDIS_TTL", 10*time.Minute),
		},
		Kafka: KafkaConfig{
			Brokers:       getStrings("KAFKA_BROKERS", []string{"localhost:9092"}),
			Topic:         getEnv("KAFKA_TOPIC", "orders.events"),
			ClientID:      getEnv("KAFKA_CLIENT_ID", "order-service"),
			TLSEnabled:    getBool("KAFKA_TLS_ENABLED", false),
			TLSServerName: getEnv("KAFKA_TLS_SERVER_NAME", ""),
			SASLEnabled:   getBool("KAFKA_SASL_ENABLED", false),
			SASLMechanism: getEnv("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512"),
			SASLUsername:  getEnv("KAFKA_SASL_USERNAME", ""),
			SASLPassword:  getEnv("KAFKA_SASL_PASSWORD", ""),
		},
		Outbox: OutboxConfig{
			PollInterval: getDuration("OUTBOX_POLL_INTERVAL", 2*time.Second),
			BatchSize:    getInt("OUTBOX_BATCH_SIZE", 100),
		},
		Observability: ObservabilityConfig{
			MetricsAddr:      getEnv("METRICS_ADDR", ":9090"),
			OTLPEndpoint:     getEnv("OTLP_ENDPOINT", ""),
			ServiceName:      getEnv("OTEL_SERVICE_NAME", "order-service"),
			TraceSampleRatio: getFloat("TRACE_SAMPLE_RATIO", 1.0),
		},
		Security: SecurityConfig{
			JWKSURL:        getEnv("JWKS_URL", ""),
			JWTIssuer:      getEnv("JWT_ISSUER", ""),
			JWTAudience:    getEnv("JWT_AUDIENCE", "order-service"),
			EncryptionKeys: getStrings("PII_ENCRYPTION_KEYS", nil),
			RateLimitRPS:   getFloat("RATE_LIMIT_RPS", 50),
			RateLimitBurst: getInt("RATE_LIMIT_BURST", 100),
			IdempotencyTTL: getDuration("IDEMPOTENCY_TTL", 24*time.Hour),
			AuthEnabled:    getBool("AUTH_ENABLED", true),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Postgres.DSN == "" {
		return fmt.Errorf("POSTGRES_DSN is required")
	}
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("KAFKA_BROKERS is required")
	}
	if c.Kafka.Topic == "" {
		return fmt.Errorf("KAFKA_TOPIC is required")
	}
	if c.Outbox.BatchSize <= 0 {
		return fmt.Errorf("OUTBOX_BATCH_SIZE must be > 0")
	}

	// PII encryption keys are mandatory: refuse to start storing PII unencrypted.
	if len(c.Security.EncryptionKeys) == 0 {
		return fmt.Errorf("PII_ENCRYPTION_KEYS is required (at least one base64 32-byte key)")
	}

	// When auth is enabled, JWKS + issuer must be configured. Zero Trust:
	// never run an authenticated service without a key source.
	if c.Security.AuthEnabled {
		if c.Security.JWKSURL == "" {
			return fmt.Errorf("JWKS_URL is required when AUTH_ENABLED=true")
		}
		if c.Security.JWTIssuer == "" {
			return fmt.Errorf("JWT_ISSUER is required when AUTH_ENABLED=true")
		}
		if c.Security.JWTAudience == "" {
			return fmt.Errorf("JWT_AUDIENCE is required when AUTH_ENABLED=true")
		}
	} else if c.Env == "prod" {
		return fmt.Errorf("AUTH_ENABLED=false is forbidden in prod")
	}
	return nil
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		switch v {
		case "1", "true", "TRUE", "True", "yes", "on":
			return true
		case "0", "false", "FALSE", "False", "no", "off":
			return false
		}
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getStrings(key string, def []string) []string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return def
}
