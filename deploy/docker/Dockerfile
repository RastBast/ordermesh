# syntax=docker/dockerfile:1.7

# ---- build stage ----
FROM golang:1.24-alpine AS build

# git is needed for VCS stamping; ca-certificates for module downloads.
RUN apk add --no-cache git ca-certificates && update-ca-certificates

WORKDIR /src

# Cache dependencies first for faster rebuilds.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Static, stripped binary. Trimpath + reproducible flags.
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/order-service ./cmd/order-service

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

# distroless static is minimal: no shell, runs as nonroot (uid 65532).
COPY --from=build /out/order-service /order-service
COPY --from=build /src/migrations /migrations

EXPOSE 8080 9090
USER nonroot:nonroot

ENTRYPOINT ["/order-service"]
