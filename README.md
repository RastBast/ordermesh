<div align="center">

# Order Service

**Production-grade, Zero-Trust order microservice in Go.**

Hexagonal architecture · Transactional Outbox · PostgreSQL · Redis · Kafka · Docker · Kubernetes

🇷🇺 [Версия на русском](README.ru.md)

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Architecture](https://img.shields.io/badge/architecture-hexagonal%20%2F%20DDD-blue)]()
[![Security](https://img.shields.io/badge/security-Zero%20Trust%20%2F%20BeyondProd-success)]()
[![Tests](https://img.shields.io/badge/tests-unit%20%2B%20integration%20%2B%20e2e-brightgreen)]()
[![Vulns](https://img.shields.io/badge/govulncheck-0%20affecting-brightgreen)]()

</div>

---

## TL;DR

A realistic e-commerce **Order** microservice that takes the boring CRUD demo and builds it the way it's actually done in production: clean dependency boundaries, reliable event publishing, encrypted PII, full authn/authz, idempotent writes, layered rate limiting, observability, and a complete container/Kubernetes delivery story — all verified by unit, integration **and** end-to-end tests against a live stack.

```bash
make up      # postgres + redis + kafka + migrations + service (Docker)
make e2e     # 39 end-to-end assertions against the running service
make test    # unit tests with -race
```

---

## Why this project exists

Most "Go microservice" samples stop at `net/http` + a SQL `INSERT`. Real services live or die on the parts those demos skip: what happens when the broker is down mid-write, how PII is protected, how retries don't double-charge a customer, how you authorize *this* user for *this* resource, and how you prove all of it keeps working. **This repo is about those parts.**

Everything here is intentional and defensible in a design review — the trade-offs are documented inline and summarized below.

---

## Architecture

Hexagonal / Ports & Adapters with a Domain-Driven core. Dependencies point **inward**: the domain knows nothing about HTTP, SQL, Redis or Kafka.

```
                 ┌──────────────────────────────────────────────┐
   HTTP (chi)    │                  adapters                     │
  ───────────►   │  httpapi   redisrepo   kafkabroker   postgres │
                 └─────┬───────────┬───────────┬──────────┬──────┘
                       │           │           │          │
                  implements   implements  implements  implements
                       ▼           ▼           ▼          ▼
                 ┌─────────────────────────────────────────────────┐
                 │                    ports                         │
                 │  Repository · Cache · Publisher · Outbox · UoW   │
                 └─────────────────────┬───────────────────────────┘
                                       │ depends on
                 ┌─────────────────────▼───────────────────────────┐
                 │              app (use cases)                     │
                 │   CreateOrder · GetOrder · ChangeStatus · Relay  │
                 └─────────────────────┬───────────────────────────┘
                                       │ depends on
                 ┌─────────────────────▼───────────────────────────┐
                 │          domain (pure business logic)            │
                 │  Order aggregate · state machine · PII VOs       │
                 └─────────────────────────────────────────────────┘
```

### Key design decisions

| Concern | Decision | Why |
|---|---|---|
| Reliable events | **Transactional Outbox** + background relay | No dual-write problem — the aggregate change and its event commit in **one DB transaction**; the relay drains to Kafka at-least-once |
| Concurrency | **Optimistic locking** (`version` column) | Safe concurrent status changes without long-held DB locks |
| Caching | Read-through Redis, invalidate on write | Fast reads, never stale after a mutation |
| Money | Integer **minor units** (cents) | Never use floats for money |
| Ordering | Kafka key = aggregate id | Per-order event ordering preserved across partitions |
| Config | Typed env vars, **validated, fail-fast** | 12-factor; refuses to start misconfigured (e.g. no PII key) |
| Errors | Domain errors mapped at the edge | Transport layer owns HTTP status codes, domain stays pure |

---

## Security — Zero Trust / BeyondProd

No implicit trust from network location. Identity is verified on every request, least privilege is enforced per-resource, and defense is layered.

**1 · Identity & transport**
- **mTLS everywhere** via Istio `PeerAuthentication: STRICT` + default-deny `AuthorizationPolicy` keyed on SPIFFE workload identities.
- **JWT verified by JWKS** — asymmetric signature check against the IdP's public keys, with key rotation, strict alg allow-list (RS/ES only — **alg-confusion attacks rejected**), and issuer/audience/expiry validation.
- **RBAC + ABAC** — fine-grained permissions (`orders.create`, `orders.read.own`, `orders.read.any`, …) from roles, plus **ownership checks** in handlers (a customer only touches their own orders; non-owners get `404`, no existence disclosure).

**2 · Data security**
- **PII encrypted at rest** — application-level **AES-256-GCM**, key-versioned for rotation without re-encryption; the order id is bound as AEAD associated data. Contact + full address live only as ciphertext.
- **PII masking** in all logs/traces — value objects implement `slog.LogValuer`, plus a scrubbing `slog.Handler` redacts card/phone patterns as a final net.
- **In transit** — TLS to Postgres & Redis; **SASL/SCRAM + TLS** to Kafka. Events carry **no PII** (ids/amounts/status only).

**3 · Application defense**
- **Idempotency** — mandatory `Idempotency-Key` on `POST`, Redis-backed with an atomic in-flight lock + unique DB index. Replays return the original response; concurrent retries get `409`; key reuse with a different body gets `422`. **No double orders.**
- **Layered rate limiting** — in-process token bucket (anti-burst) **and** a Redis GCRA quota shared across replicas, keyed by principal.
- **Graceful shutdown** — `signal.NotifyContext` + `errgroup` drain HTTP, the relay and metrics cleanly on SIGTERM.
- Request body limits, `DisallowUnknownFields`, strict timeouts, security headers (CSP/HSTS/nosniff/frame-deny).

**4 · DevSecOps**
- **`govulncheck`** in CI (call-graph analysis → **0 affecting vulnerabilities**) + gitleaks secret scanning.
- **Distroless, non-root, read-only-rootfs** image — no shell, no package manager, dropped capabilities, seccomp `RuntimeDefault`.

---

## Domain model

An order is an aggregate root with a strict state machine and PII-bearing value objects.

```
PENDING ──► PAID ──► SHIPPED
   │          │
   └──────────┴────► CANCELLED        (SHIPPED & CANCELLED are terminal)
```

Illegal transitions return `409`; the `version` token guards against lost updates. Items, payment method, currency consistency and contact/address are validated in the domain constructor — invalid input never reaches the database.

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Go 1.24 |
| HTTP | chi + stdlib `net/http`, `log/slog` |
| Database | PostgreSQL via `pgx/v5` (pool, transactions, JSONB) |
| Cache | Redis via `go-redis/v9` |
| Broker | Kafka via `segmentio/kafka-go` (SASL/TLS-capable) |
| Auth | `golang-jwt/v5` + self-contained JWKS client |
| Crypto | stdlib `crypto/aes` + `cipher.GCM` (key-versioned keyring) |
| Observability | Prometheus, OpenTelemetry (OTLP) |
| Migrations | `golang-migrate` |
| Tests | stdlib `testing`, `testcontainers-go`, race detector |
| Delivery | Multi-stage Docker (distroless), Kubernetes manifests, Helm chart |
| CI | GitHub Actions: lint · test · integration · govulncheck · gitleaks · image build |

---

## Project layout

```
cmd/order-service/        # main: wiring + graceful shutdown
internal/
  domain/                 # aggregate, state machine, PII value objects (pure)
  app/                    # use cases + outbox relay + concurrency/bench tests
  ports/                  # interfaces (Repository, Cache, Publisher, Outbox, UoW)
  adapters/
    httpapi/              # chi router, handlers, auth/idempotency/rate-limit middleware
    repository/postgres/  # pgx repo, unit of work, outbox store (+ PII encryption)
    cache/redisrepo/      # Redis read-through cache
    broker/kafkabroker/   # Kafka publisher
  security/
    auth/                 # JWT + JWKS verifier, RBAC/ABAC, principal
    crypto/               # AES-256-GCM key-versioned keyring (PII at rest)
    pii/                  # masking + scrubbing slog handler
    idempotency/          # Redis-backed replay protection
    ratelimit/            # local token bucket + distributed GCRA
  platform/               # infra builders: pg, redis, kafka, logger, metrics, tracing
  config/                 # typed, validated env config
migrations/               # SQL migrations
deploy/
  docker/                 # Dockerfile (distroless) + docker-compose stack
  k8s/                    # Deployment, Service, HPA, PDB, ConfigMap, Secret, Istio mTLS
  helm/order-service/     # Helm chart
scripts/e2e-smoke.sh      # 39-assertion end-to-end acceptance test
test/integration/         # testcontainers e2e (real Postgres + Redis)
api/openapi.yaml          # OpenAPI 3 spec
.github/workflows/ci.yml  # CI pipeline
```

---

## Quick start

```bash
make up        # build + start the full stack (Docker)
make logs      # follow service logs
make down      # stop and clean up
```

Create an order (note the mandatory `Idempotency-Key`):

```bash
curl -s -X POST localhost:8080/v1/orders \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  -d '{
    "customer_id":"11111111-1111-1111-1111-111111111111",
    "payment_method":"CARD",
    "contact":{"full_name":"Ada Lovelace","email":"ada@example.com","phone":"+1 415 555 1234"},
    "shipping_address":{"line1":"1 Main St","city":"London","postal_code":"EC1","country":"GB"},
    "items":[{"sku":"SKU-1","name":"Widget","quantity":2,"unit_price":1500,"currency":"USD"}]
  }' | jq
```

API: `:8080` · Prometheus metrics: `:9090/metrics` · OpenAPI: [`api/openapi.yaml`](api/openapi.yaml)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/orders` | Create order (idempotent) |
| `GET` | `/v1/orders` | List (filters: `customer_id`, `status`, `limit`, `offset`) |
| `GET` | `/v1/orders/{id}` | Get order |
| `PATCH` | `/v1/orders/{id}/status` | Change status |
| `GET` | `/healthz` · `/readyz` | Liveness / readiness |

---

## Testing strategy

Three layers, each catching a different class of bug:

```bash
make test     # unit tests + race detector + coverage
make itest    # integration: real Postgres + Redis via testcontainers
make e2e      # 39 assertions against the LIVE running stack
make audit    # fmt + vet + lint + test + govulncheck (full gate)
```

- **Domain & application** — table-driven unit tests; the use-case layer is tested against in-memory fakes for every port (fast, no I/O).
- **Security** — dedicated tests: AES round-trip / tamper / **key rotation**, JWT expiry / audience / issuer / **alg-confusion rejection**, PII masking, rate-limit bursts.
- **Concurrency** — `TestConcurrentCreate` (500 parallel creates) and `TestConcurrentStatusChange` (contended optimistic locking) run clean under `-race`; plus a `BenchmarkCreateOrder`.
- **Integration** — boots real Postgres & Redis and asserts the full create → encrypt-at-rest → cache → transition → outbox flow.
- **End-to-end** — `scripts/e2e-smoke.sh` hits the live service and verifies idempotency (including a 20× concurrent race), the state machine, **PII ciphertext in the DB**, **outbox → Kafka delivery with no PII leak**, metrics and security headers.

> The e2e script generates a unique idempotency key per run — by design, a fixed key would correctly *replay* a finished order forever (idempotency keys are permanent). That behavior is a feature, not a bug.

---

## Kubernetes

```bash
kubectl apply -f deploy/k8s/                    # raw manifests
# or
helm upgrade --install order-service deploy/helm/order-service \
  --namespace orders --create-namespace --set image.tag=1.0.0
```

Includes: rolling updates with surge, HPA, PodDisruptionBudget, startup/liveness/readiness probes, DB migrations as an init container, distroless non-root pod security context, and Istio STRICT mTLS + authorization policies.

---

## About the author

I'm a backend engineer with **6+ years of commercial Go experience**, building and operating distributed systems in production.

**What I work with day to day**
- **Go** — idiomatic, well-tested services; clean architecture (hexagonal / DDD); careful concurrency with the race detector and profiling.
- **Data & messaging** — PostgreSQL (pgx, transactions, query tuning), Redis, **Apache Kafka** with event-driven patterns like the **transactional outbox**, idempotent consumers and per-key ordering.
- **Reliability** — graceful shutdown, optimistic concurrency, retries/backoff, health/readiness, the "what happens when a dependency is down" thinking.
- **Security** — Zero-Trust / BeyondProd practices: mTLS, JWT/JWKS, RBAC/ABAC, encryption at rest, PII handling, `govulncheck` in CI.
- **Delivery & ops** — Docker (distroless), Kubernetes, Helm, GitHub Actions, Prometheus/OpenTelemetry observability.

**How I approach engineering**
This project is a snapshot of how I like to build: every non-obvious decision is documented, the boundaries are clean enough to swap any adapter, and *correctness is proven by tests at three levels* rather than asserted. I care about the failure modes as much as the happy path — that's where production systems are actually won.

This service compiles, the full test suite is green, and `govulncheck` reports **0 affecting vulnerabilities**.

> 📫 Open to backend / platform Go roles. Happy to walk through any design decision in this repo.

---

## Production checklist (next steps)

- [ ] Source secrets from Vault / External Secrets / Sealed Secrets; rotate `PII_ENCRYPTION_KEYS` via KMS (append a new key).
- [ ] Kafka topic **ACLs**: grant `WRITE` on `orders.events` only.
- [ ] Schema registry (Avro/Protobuf) for event schema evolution.
- [ ] Dead-letter handling + alerting on `outbox_pending_events` growth.
- [ ] Run the outbox relay as a separately scalable deployment if needed.
