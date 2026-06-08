SHELL := /bin/bash
APP := order-service
PKG := github.com/RastBast/ordermesh-
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE ?= ghcr.io/example/$(APP):$(VERSION)

COMPOSE := docker compose -f deploy/docker/docker-compose.yml

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(APP) ./cmd/$(APP)

.PHONY: run
run: ## Run locally
	go run ./cmd/$(APP)

.PHONY: test
test: ## Run unit tests with race detector and coverage
	go test -race -count=1 -coverprofile=coverage.out ./...

.PHONY: cover
cover: test ## Show coverage in browser
	go tool cover -html=coverage.out

.PHONY: itest
itest: ## Run integration tests (requires Docker)
	go test -tags=integration -count=1 ./test/...

.PHONY: e2e
e2e: ## Hard end-to-end acceptance test against a running stack (make up first)
	./scripts/e2e-smoke.sh

.PHONY: audit
audit: ## Full quality gate: fmt-check, vet, lint, test, govulncheck
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	golangci-lint run ./... || true
	go test -race -count=1 ./...
	govulncheck ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -f deploy/docker/Dockerfile -t $(IMAGE) --build-arg VERSION=$(VERSION) .

.PHONY: up
up: ## Start the full local stack (postgres, redis, kafka, app)
	$(COMPOSE) up --build -d

.PHONY: down
down: ## Stop the local stack
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail app logs
	$(COMPOSE) logs -f order-service

.PHONY: migrate-up
migrate-up: ## Apply DB migrations against local Postgres
	migrate -path migrations -database "postgres://order:order@localhost:5432/orders?sslmode=disable" up

.PHONY: migrate-down
migrate-down: ## Roll back the last migration
	migrate -path migrations -database "postgres://order:order@localhost:5432/orders?sslmode=disable" down 1

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart
	helm lint deploy/helm/order-service

.PHONY: helm-template
helm-template: ## Render the Helm chart
	helm template order-service deploy/helm/order-service
