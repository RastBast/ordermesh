package domain

import (
	"time"

	"github.com/google/uuid"
)

// EventType enumerates domain events published to the broker.
type EventType string

const (
	EventOrderCreated   EventType = "order.created"
	EventOrderPaid      EventType = "order.paid"
	EventOrderShipped   EventType = "order.shipped"
	EventOrderCancelled EventType = "order.cancelled"
)

// EventForStatus maps a resulting status to the event that announces it.
func EventForStatus(s Status) EventType {
	switch s {
	case StatusPaid:
		return EventOrderPaid
	case StatusShipped:
		return EventOrderShipped
	case StatusCancelled:
		return EventOrderCancelled
	default:
		return EventOrderCreated
	}
}

// Event is the canonical envelope persisted into the outbox and published
// to Kafka. It is transport-agnostic and JSON-serialisable.
type Event struct {
	ID            uuid.UUID `json:"id"`
	Type          EventType `json:"type"`
	AggregateID   uuid.UUID `json:"aggregate_id"`
	AggregateType string    `json:"aggregate_type"`
	OccurredAt    time.Time `json:"occurred_at"`
	Payload       []byte    `json:"payload"`
}

// NewEvent builds an event envelope with a fresh id and timestamp.
func NewEvent(t EventType, aggregateID uuid.UUID, payload []byte) Event {
	return Event{
		ID:            uuid.New(),
		Type:          t,
		AggregateID:   aggregateID,
		AggregateType: "order",
		OccurredAt:    time.Now().UTC(),
		Payload:       payload,
	}
}
