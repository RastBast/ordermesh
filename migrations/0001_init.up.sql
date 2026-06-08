-- Orders aggregate and transactional outbox.
-- Designed for the goose / golang-migrate tooling.
--
-- Security notes:
--   * PII (contact, full shipping address) is stored ENCRYPTED at the
--     application layer (AES-256-GCM, key-versioned) in *_enc columns. Only
--     low-sensitivity fields needed for filtering/analytics (city, country)
--     are kept in plaintext.
--   * Enable PostgreSQL TDE / encrypted volumes for encryption-at-rest of the
--     whole cluster as an additional layer (defence in depth).

CREATE TABLE IF NOT EXISTS orders (
    id                   UUID PRIMARY KEY,
    customer_id          UUID        NOT NULL,
    status               TEXT        NOT NULL CHECK (status IN ('PENDING','PAID','SHIPPED','CANCELLED')),
    items                JSONB       NOT NULL,
    total_price          BIGINT      NOT NULL CHECK (total_price >= 0),
    currency             TEXT        NOT NULL,
    payment_method       TEXT        NOT NULL CHECK (payment_method IN ('CARD','PAYPAL','APPLE_PAY')),

    -- Encrypted PII (base64 of keyID||nonce||ciphertext+tag). Never logged.
    contact_enc          TEXT        NOT NULL,
    shipping_address_enc TEXT        NOT NULL,

    -- Low-sensitivity, queryable subset of the address.
    ship_city            TEXT        NOT NULL,
    ship_country         CHAR(2)     NOT NULL,

    -- Audit link to the request that created the order.
    idempotency_key      TEXT,

    version              BIGINT      NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders (customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_status      ON orders (status);
CREATE INDEX IF NOT EXISTS idx_orders_created_at  ON orders (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_country     ON orders (ship_country);

-- One order per idempotency key (defence in depth alongside the Redis guard).
CREATE UNIQUE INDEX IF NOT EXISTS uq_orders_idempotency_key
    ON orders (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Transactional outbox: written in the same tx as the aggregate change.
CREATE TABLE IF NOT EXISTS outbox (
    id             UUID PRIMARY KEY,
    aggregate_id   UUID        NOT NULL,
    aggregate_type TEXT        NOT NULL,
    type           TEXT        NOT NULL,
    payload        JSONB       NOT NULL,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    published      BOOLEAN     NOT NULL DEFAULT false,
    published_at   TIMESTAMPTZ
);

-- Partial index makes the relay's "WHERE published = false" scan cheap.
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished
    ON outbox (occurred_at)
    WHERE published = false;
