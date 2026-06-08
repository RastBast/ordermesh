#!/usr/bin/env fish
#
# setup-macos.fish — one-shot setup for the Order Service on macOS (fish shell).
#
# What it does:
#   1. Installs all tooling via Homebrew (Go, Docker, kubectl, helm, etc.).
#   2. Extracts order-service.tar.gz into ~/Projects/order-service.
#   3. Generates a local PII encryption key and writes .env.
#   4. Downloads Go modules and runs build + tests to verify.
#
# Usage (from the folder where order-service.tar.gz is, e.g. ~/Downloads):
#   chmod +x setup-macos.fish
#   ./setup-macos.fish
#
# Re-running is safe (idempotent).

set -l ARCHIVE order-service.tar.gz
set -l PROJECTS_DIR "$HOME/Projects"
set -l PROJECT_DIR "$PROJECTS_DIR/order-service"

function info;  set_color cyan;  echo "▶ $argv"; set_color normal; end
function ok;    set_color green; echo "✓ $argv"; set_color normal; end
function warn;  set_color yellow; echo "! $argv"; set_color normal; end
function fail;  set_color red;   echo "✗ $argv"; set_color normal; end

# ---------------------------------------------------------------------------
# 1. Homebrew + tooling
# ---------------------------------------------------------------------------
if not type -q brew
    info "Homebrew not found — installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # add brew to this fish session (Apple Silicon path)
    if test -d /opt/homebrew/bin
        fish_add_path /opt/homebrew/bin
    end
end
ok "Homebrew present"

info "Installing CLI tools (go, docker, kubectl, helm, kafka, postgres client, redis, golang-migrate, golangci-lint)..."
brew install go golangci-lint golang-migrate kubectl helm kafka libpq redis jq; or warn "some brew formulae may already be installed"

# Docker Desktop is a cask (provides the docker engine + compose).
if not type -q docker
    info "Installing Docker Desktop..."
    brew install --cask docker; or warn "install Docker Desktop manually if this failed"
    warn "Open Docker Desktop once so the engine starts, then re-run if needed."
end

# govulncheck (DevSecOps dependency scanner)
info "Installing govulncheck..."
go install golang.org/x/vuln/cmd/govulncheck@latest; or warn "govulncheck install skipped"

ok "Tooling installed"

# ---------------------------------------------------------------------------
# 2. Extract project
# ---------------------------------------------------------------------------
if not test -f $ARCHIVE
    fail "$ARCHIVE not found in "(pwd)". Put it here (e.g. ~/Downloads) and re-run."
    exit 1
end

mkdir -p $PROJECTS_DIR
if test -d $PROJECT_DIR
    warn "$PROJECT_DIR already exists — backing it up"
    mv $PROJECT_DIR "$PROJECT_DIR.bak."(date +%s)
end

info "Extracting $ARCHIVE into $PROJECTS_DIR ..."
tar -xzf $ARCHIVE -C $PROJECTS_DIR
ok "Extracted to $PROJECT_DIR"

cd $PROJECT_DIR

# ---------------------------------------------------------------------------
# 3. Local .env with a freshly generated PII key
# ---------------------------------------------------------------------------
if not test -f .env
    info "Creating .env (auth disabled for local dev, fresh PII key)..."
    set -l PII_KEY (head -c 32 /dev/urandom | base64)
    begin
        echo "APP_ENV=dev"
        echo "LOG_LEVEL=debug"
        echo "HTTP_ADDR=:8080"
        echo "METRICS_ADDR=:9090"
        echo "POSTGRES_DSN=postgres://order:order@localhost:5432/orders?sslmode=disable"
        echo "REDIS_ADDR=localhost:6379"
        echo "KAFKA_BROKERS=localhost:9092"
        echo "KAFKA_TOPIC=orders.events"
        echo "AUTH_ENABLED=false"
        echo "PII_ENCRYPTION_KEYS=$PII_KEY"
        echo "RATE_LIMIT_RPS=50"
        echo "RATE_LIMIT_BURST=100"
        echo "IDEMPOTENCY_TTL=24h"
    end > .env
    ok ".env created"
else
    ok ".env already exists (left untouched)"
end

# ---------------------------------------------------------------------------
# 4. Build & verify
# ---------------------------------------------------------------------------
info "Downloading Go modules..."
go mod download
info "Building..."
go build ./...; and ok "build OK"; or begin; fail "build failed"; exit 1; end
info "Running unit tests (race detector)..."
go test -race -count=1 ./...; and ok "tests OK"; or warn "some tests failed — check output"

echo
ok "Setup complete!"
set_color magenta
echo "Project: $PROJECT_DIR"
echo
echo "Next steps:"
echo "  cd $PROJECT_DIR"
echo "  make up        # start postgres + redis + kafka + the service (Docker)"
echo "  make logs      # follow logs"
echo "  open nvim ."
set_color normal
