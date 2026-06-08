// Package kafka builds a segmentio/kafka-go writer used by the broker adapter,
// with optional SASL/SCRAM authentication and TLS for in-transit security.
package kafka

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/RastBast/ordermesh-/internal/config"
)

// NewWriter returns a Kafka writer configured for durability and, when enabled,
// SASL/SCRAM auth + TLS. Hash balancer keeps per-aggregate ordering by routing
// the same key to the same partition.
func NewWriter(cfg config.KafkaConfig) (*kafka.Writer, error) {
	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll, // durability: wait for all in-sync replicas
		BatchTimeout: 50 * time.Millisecond,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Async:        false, // synchronous so the outbox relay can confirm delivery
		Compression:  kafka.Snappy,
		Transport:    transport,
	}, nil
}

// newTransport builds the SASL/TLS transport from config.
func newTransport(cfg config.KafkaConfig) (*kafka.Transport, error) {
	t := &kafka.Transport{
		ClientID:    cfg.ClientID,
		DialTimeout: 10 * time.Second,
	}

	if cfg.TLSEnabled {
		t.TLS = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: cfg.TLSServerName,
		}
	}

	if cfg.SASLEnabled {
		mech, err := saslMechanism(cfg)
		if err != nil {
			return nil, err
		}
		t.SASL = mech
	}
	return t, nil
}

func saslMechanism(cfg config.KafkaConfig) (sasl.Mechanism, error) {
	switch cfg.SASLMechanism {
	case "PLAIN":
		return plain.Mechanism{Username: cfg.SASLUsername, Password: cfg.SASLPassword}, nil
	case "SCRAM-SHA-256":
		return scram.Mechanism(scram.SHA256, cfg.SASLUsername, cfg.SASLPassword)
	case "SCRAM-SHA-512", "":
		return scram.Mechanism(scram.SHA512, cfg.SASLUsername, cfg.SASLPassword)
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism %q", cfg.SASLMechanism)
	}
}
