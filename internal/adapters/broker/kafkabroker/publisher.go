// Package kafkabroker implements ports.Publisher on segmentio/kafka-go.
package kafkabroker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/segmentio/kafka-go"

	"github.com/RastBast/ordermesh-/internal/domain"
	"github.com/RastBast/ordermesh-/internal/ports"
)

// Publisher writes domain events to Kafka. The aggregate id is used as the
// message key to preserve per-order ordering across partitions.
type Publisher struct {
	writer *kafka.Writer
}

// New constructs the Kafka publisher.
func New(writer *kafka.Writer) *Publisher {
	return &Publisher{writer: writer}
}

// envelope is the wire format written to Kafka.
type envelope struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	AggregateID   string          `json:"aggregate_id"`
	AggregateType string          `json:"aggregate_type"`
	OccurredAt    string          `json:"occurred_at"`
	Payload       json.RawMessage `json:"payload"`
}

// Publish sends a single event synchronously.
func (p *Publisher) Publish(ctx context.Context, e domain.Event) error {
	env := envelope{
		ID:            e.ID.String(),
		Type:          string(e.Type),
		AggregateID:   e.AggregateID.String(),
		AggregateType: e.AggregateType,
		OccurredAt:    e.OccurredAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		Payload:       e.Payload,
	}
	value, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(e.AggregateID.String()),
		Value: value,
		Headers: []kafka.Header{
			{Key: "event_type", Value: []byte(e.Type)},
			{Key: "event_id", Value: []byte(e.ID.String())},
			{Key: "content_type", Value: []byte("application/json")},
		},
	}
	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("write kafka message: %w", err)
	}
	return nil
}

// Close flushes and closes the underlying writer.
func (p *Publisher) Close() error {
	return p.writer.Close()
}

var _ ports.Publisher = (*Publisher)(nil)
