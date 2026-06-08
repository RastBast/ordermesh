<div align="center">

# Order Service

**Продакшен-микросервис заказов на Go с архитектурой Zero Trust.**

Гексагональная архитектура · Transactional Outbox · PostgreSQL · Redis · Kafka · Docker · Kubernetes

🇬🇧 [English version](README.md)

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Architecture](https://img.shields.io/badge/архитектура-hexagonal%20%2F%20DDD-blue)]()
[![Security](https://img.shields.io/badge/безопасность-Zero%20Trust%20%2F%20BeyondProd-success)]()
[![Tests](https://img.shields.io/badge/тесты-unit%20%2B%20integration%20%2B%20e2e-brightgreen)]()
[![Vulns](https://img.shields.io/badge/govulncheck-0%20уязвимостей-brightgreen)]()

</div>

---

## Коротко

Реалистичный микросервис **заказов** для e-commerce, собранный не как «учебный CRUD», а так, как это делают в проде: чистые границы зависимостей, надёжная публикация событий, шифрование PII, полноценные аутентификация и авторизация, идемпотентные записи, многоуровневый rate limiting, наблюдаемость и полный путь доставки (Docker/Kubernetes) — и всё это проверено unit-, integration- **и** end-to-end-тестами по живому стенду.

```bash
make up      # postgres + redis + kafka + миграции + сервис (Docker)
make e2e     # 39 end-to-end проверок по работающему сервису
make test    # юнит-тесты с -race
```

---

## Зачем этот проект

Большинство «примеров микросервиса на Go» заканчиваются на `net/http` + один `INSERT`. Но реальные сервисы живут или умирают на том, что эти примеры пропускают: что будет, если брокер упал в середине записи, как защищены персональные данные, как ретраи не приводят к двойному списанию, как авторизовать *именно этого* пользователя на *именно этот* ресурс и как доказать, что всё это продолжает работать. **Этот репозиторий — именно про эти части.**

Каждое нетривиальное решение здесь осознанное и его можно защитить на дизайн-ревью — компромиссы задокументированы прямо в коде и сведены ниже.

---

## Архитектура

Гексагональная (Ports & Adapters) с предметным ядром в духе DDD. Зависимости направлены **внутрь**: домен ничего не знает про HTTP, SQL, Redis и Kafka.

```
                 ┌──────────────────────────────────────────────┐
   HTTP (chi)    │                  adapters                     │
  ───────────►   │  httpapi   redisrepo   kafkabroker   postgres │
                 └─────┬───────────┬───────────┬──────────┬──────┘
                       │           │           │          │
                  реализует    реализует   реализует   реализует
                       ▼           ▼           ▼          ▼
                 ┌─────────────────────────────────────────────────┐
                 │                    ports                         │
                 │  Repository · Cache · Publisher · Outbox · UoW   │
                 └─────────────────────┬───────────────────────────┘
                                       │ зависит от
                 ┌─────────────────────▼───────────────────────────┐
                 │              app (сценарии)                      │
                 │   CreateOrder · GetOrder · ChangeStatus · Relay  │
                 └─────────────────────┬───────────────────────────┘
                                       │ зависит от
                 ┌─────────────────────▼───────────────────────────┐
                 │          domain (чистая бизнес-логика)           │
                 │  агрегат Order · машина состояний · PII VO       │
                 └─────────────────────────────────────────────────┘
```

### Ключевые проектные решения

| Задача | Решение | Почему так |
|---|---|---|
| Надёжные события | **Transactional Outbox** + фоновый relay | Нет проблемы двойной записи — изменение агрегата и его событие коммитятся в **одной транзакции БД**; relay доставляет в Kafka at-least-once |
| Конкурентность | **Оптимистичная блокировка** (колонка `version`) | Безопасная конкурентная смена статусов без долгих блокировок БД |
| Кэширование | Read-through Redis, инвалидация при записи | Быстрые чтения и никогда не устаревшие данные после мутации |
| Деньги | Целые **минорные единицы** (центы) | Никогда не используем float для денег |
| Порядок событий | Ключ Kafka = id агрегата | Сохраняется порядок событий по конкретному заказу между партициями |
| Конфигурация | Типизированные env, **валидация, fail-fast** | 12-factor; сервис не стартует с некорректным конфигом (например, без PII-ключа) |
| Ошибки | Доменные ошибки маппятся на границе | Транспортный слой владеет HTTP-кодами, домен остаётся чистым |

---

## Безопасность — Zero Trust / BeyondProd

Никакого неявного доверия по сетевому расположению. Личность проверяется на каждом запросе, принцип наименьших привилегий применяется на уровне ресурса, защита — многослойная.

**1 · Идентификация и транспорт**
- **mTLS повсюду** через Istio `PeerAuthentication: STRICT` + default-deny `AuthorizationPolicy` по SPIFFE-идентичностям ворклоадов.
- **JWT, проверяемый через JWKS** — асимметричная проверка подписи по публичным ключам IdP, с ротацией ключей, строгим allow-list алгоритмов (только RS/ES — **атаки alg-confusion отвергаются**) и валидацией issuer/audience/срока действия.
- **RBAC + ABAC** — гранулярные права (`orders.create`, `orders.read.own`, `orders.read.any`, …) из ролей, плюс **проверка владельца** в хэндлерах (клиент работает только со своими заказами; чужие → `404`, без раскрытия факта существования).

**2 · Защита данных**
- **PII зашифрованы at rest** — на уровне приложения **AES-256-GCM**, с версионированием ключей для ротации без перешифровки; id заказа привязан как AEAD associated data. Контакты и полный адрес хранятся только в виде шифртекста.
- **Маскирование PII** во всех логах/трейсах — value-объекты реализуют `slog.LogValuer`, плюс scrubbing-`slog.Handler` вычищает паттерны карт/телефонов как последний рубеж.
- **В транзите** — TLS к Postgres и Redis; **SASL/SCRAM + TLS** к Kafka. В событиях **нет PII** (только id/суммы/статус).

**3 · Защита приложения**
- **Идемпотентность** — обязательный `Idempotency-Key` на `POST`, на базе Redis с атомарной in-flight-блокировкой + уникальный индекс в БД. Повтор возвращает исходный ответ; конкурентные ретраи получают `409`; reuse ключа с другим телом → `422`. **Никаких двойных заказов.**
- **Многоуровневый rate limiting** — локальный token bucket (анти-бёрст) **и** распределённая GCRA-квота на всех репликах, по ключу принципала.
- **Graceful shutdown** — `signal.NotifyContext` + `errgroup` корректно завершают HTTP, relay и метрики по SIGTERM.
- Лимиты тела запроса, `DisallowUnknownFields`, строгие таймауты, security-заголовки (CSP/HSTS/nosniff/frame-deny).

**4 · DevSecOps**
- **`govulncheck`** в CI (анализ графа вызовов → **0 затрагивающих уязвимостей**) + сканирование секретов gitleaks.
- **Distroless, non-root, read-only-rootfs** образ — без shell, без пакетного менеджера, со сброшенными capabilities и seccomp `RuntimeDefault`.

---

## Предметная модель

Заказ — это агрегат-корень со строгой машиной состояний и value-объектами, содержащими PII.

```
PENDING ──► PAID ──► SHIPPED
   │          │
   └──────────┴────► CANCELLED        (SHIPPED и CANCELLED — терминальные)
```

Недопустимые переходы возвращают `409`; токен `version` защищает от потерянных обновлений. Позиции, способ оплаты, единство валюты и контакты/адрес валидируются в конструкторе домена — некорректные данные никогда не доходят до БД.

---

## Технологический стек

| Слой | Выбор |
|---|---|
| Язык | Go 1.24 |
| HTTP | chi + stdlib `net/http`, `log/slog` |
| База данных | PostgreSQL через `pgx/v5` (пул, транзакции, JSONB) |
| Кэш | Redis через `go-redis/v9` |
| Брокер | Kafka через `segmentio/kafka-go` (с поддержкой SASL/TLS) |
| Auth | `golang-jwt/v5` + собственный JWKS-клиент |
| Криптография | stdlib `crypto/aes` + `cipher.GCM` (версионированный keyring) |
| Наблюдаемость | Prometheus, OpenTelemetry (OTLP) |
| Миграции | `golang-migrate` |
| Тесты | stdlib `testing`, `testcontainers-go`, race detector |
| Доставка | Многостадийный Docker (distroless), манифесты Kubernetes, Helm-чарт |
| CI | GitHub Actions: lint · test · integration · govulncheck · gitleaks · сборка образа |

---

## Структура проекта

```
cmd/order-service/        # main: связывание зависимостей + graceful shutdown
internal/
  domain/                 # агрегат, машина состояний, PII value-объекты (чистый код)
  app/                    # сценарии + outbox relay + тесты конкурентности/бенчмарк
  ports/                  # интерфейсы (Repository, Cache, Publisher, Outbox, UoW)
  adapters/
    httpapi/              # chi-роутер, хэндлеры, middleware auth/idempotency/rate-limit
    repository/postgres/  # pgx-репозиторий, unit of work, outbox store (+ шифрование PII)
    cache/redisrepo/      # read-through кэш на Redis
    broker/kafkabroker/   # Kafka-паблишер
  security/
    auth/                 # JWT + JWKS verifier, RBAC/ABAC, принципал
    crypto/               # AES-256-GCM версионированный keyring (PII at rest)
    pii/                  # маскирование + scrubbing slog-хэндлер
    idempotency/          # защита от повторов на Redis
    ratelimit/            # локальный token bucket + распределённый GCRA
  platform/               # инфраструктурные билдеры: pg, redis, kafka, logger, метрики, трейсинг
  config/                 # типизированный, валидируемый env-конфиг
migrations/               # SQL-миграции
deploy/
  docker/                 # Dockerfile (distroless) + docker-compose стек
  k8s/                    # Deployment, Service, HPA, PDB, ConfigMap, Secret, Istio mTLS
  helm/order-service/     # Helm-чарт
scripts/e2e-smoke.sh      # end-to-end приёмочный тест на 39 проверок
test/integration/         # testcontainers e2e (реальные Postgres + Redis)
api/openapi.yaml          # спецификация OpenAPI 3
.github/workflows/ci.yml  # пайплайн CI
```

---

## Быстрый старт

```bash
make up        # собрать + поднять весь стек (Docker)
make logs      # смотреть логи сервиса
make down      # остановить и очистить
```

Создать заказ (обрати внимание на обязательный `Idempotency-Key`):

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

API: `:8080` · Метрики Prometheus: `:9090/metrics` · OpenAPI: [`api/openapi.yaml`](api/openapi.yaml)

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/v1/orders` | Создать заказ (идемпотентно) |
| `GET` | `/v1/orders` | Список (фильтры: `customer_id`, `status`, `limit`, `offset`) |
| `GET` | `/v1/orders/{id}` | Получить заказ |
| `PATCH` | `/v1/orders/{id}/status` | Сменить статус |
| `GET` | `/healthz` · `/readyz` | Liveness / readiness |

---

## Стратегия тестирования

Три уровня, каждый ловит свой класс ошибок:

```bash
make test     # юнит-тесты + race detector + покрытие
make itest    # интеграция: реальные Postgres + Redis через testcontainers
make e2e      # 39 проверок по ЖИВОМУ работающему стеку
make audit    # fmt + vet + lint + test + govulncheck (полный гейт)
```

- **Домен и приложение** — табличные юнит-тесты; слой сценариев тестируется на in-memory фейках для всех портов (быстро, без I/O).
- **Безопасность** — отдельные тесты: AES round-trip / порча шифртекста / **ротация ключей**, JWT срок / audience / issuer / **отказ при alg-confusion**, маскирование PII, бёрсты rate limiter.
- **Конкурентность** — `TestConcurrentCreate` (500 параллельных созданий) и `TestConcurrentStatusChange` (конкуренция за оптимистичную блокировку) проходят чисто под `-race`; плюс `BenchmarkCreateOrder`.
- **Интеграция** — поднимает реальные Postgres и Redis и проверяет полный цикл: создание → шифрование at-rest → кэш → переход → outbox.
- **End-to-end** — `scripts/e2e-smoke.sh` бьёт по живому сервису и проверяет идемпотентность (включая гонку из 20 параллельных запросов), машину состояний, **шифртекст PII в БД**, **доставку outbox → Kafka без утечки PII**, метрики и security-заголовки.

> Скрипт e2e генерирует уникальный idempotency-ключ на каждый запуск — по дизайну фиксированный ключ корректно *повторял* бы завершённый заказ вечно (idempotency-ключи постоянны). Это поведение — фича, а не баг.

---

## Kubernetes

```bash
kubectl apply -f deploy/k8s/                    # сырые манифесты
# или
helm upgrade --install order-service deploy/helm/order-service \
  --namespace orders --create-namespace --set image.tag=1.0.0
```

Включает: rolling-обновления с surge, HPA, PodDisruptionBudget, startup/liveness/readiness-пробы, миграции БД как init-контейнер, distroless non-root security context и Istio STRICT mTLS + политики авторизации.

---

## Об авторе

Я backend-инженер с **более чем 6 годами коммерческого опыта на Go**, проектирую и эксплуатирую распределённые системы в продакшене.

**С чем работаю каждый день**
- **Go** — идиоматичный, хорошо покрытый тестами код; чистая архитектура (hexagonal / DDD); аккуратная работа с конкурентностью через race detector и профилирование.
- **Данные и сообщения** — PostgreSQL (pgx, транзакции, тюнинг запросов), Redis, **Apache Kafka** с event-driven паттернами: **transactional outbox**, идемпотентные консьюмеры, порядок по ключу.
- **Надёжность** — graceful shutdown, оптимистичная конкурентность, ретраи/backoff, health/readiness, мышление в духе «что будет, когда зависимость упадёт».
- **Безопасность** — практики Zero-Trust / BeyondProd: mTLS, JWT/JWKS, RBAC/ABAC, шифрование at rest, работа с PII, `govulncheck` в CI.
- **Доставка и эксплуатация** — Docker (distroless), Kubernetes, Helm, GitHub Actions, наблюдаемость на Prometheus/OpenTelemetry.

**Как я подхожу к инженерии**
Этот проект — срез того, как я люблю строить: каждое неочевидное решение задокументировано, границы достаточно чистые, чтобы заменить любой адаптер, а *корректность доказана тестами на трёх уровнях*, а не заявлена на словах. Меня интересуют сценарии отказа не меньше happy path — именно там по-настоящему выигрываются продакшен-системы.

Сервис компилируется, весь набор тестов зелёный, а `govulncheck` сообщает **0 затрагивающих уязвимостей**.

> 📫 Открыт к предложениям по backend / platform ролям на Go. С удовольствием разберу любое архитектурное решение из этого репозитория.

---

## Чек-лист до прода (следующие шаги)

- [ ] Брать секреты из Vault / External Secrets / Sealed Secrets; ротировать `PII_ENCRYPTION_KEYS` через KMS (добавлением нового ключа).
- [ ] ACL топиков Kafka: давать `WRITE` только на `orders.events`.
- [ ] Schema registry (Avro/Protobuf) для эволюции схемы событий.
- [ ] Обработка dead-letter + алерты на рост `outbox_pending_events`.
- [ ] Вынести outbox relay в отдельно масштабируемый деплой при необходимости.
