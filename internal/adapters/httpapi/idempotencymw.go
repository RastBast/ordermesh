package httpapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/RastBast/ordermesh-/internal/security/idempotency"
)

// IdempotencyStore is the dependency for the middleware (satisfied by *idempotency.Store).
type IdempotencyStore interface {
	Begin(ctx context.Context, key, requestHash string) (*idempotency.Record, bool, error)
	Complete(ctx context.Context, key string, rec idempotency.Record) error
	Abort(ctx context.Context, key string) error
}

// captureWriter buffers the response so a successful result can be persisted
// for idempotent replay.
type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

// IdempotencyMiddleware protects mutating requests (POST) against replays via
// the Idempotency-Key header. Identical retries return the original response;
// concurrent retries get 409; key reuse with a different body gets 422.
func IdempotencyMiddleware(store IdempotencyStore, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only guard unsafe methods that create resources.
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			idemKey := r.Header.Get("Idempotency-Key")
			if idemKey == "" {
				// Make idempotency mandatory for create endpoints (anti double-charge).
				writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
				return
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if err != nil {
				writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			reqHash := idempotency.HashRequest(r.Method, r.URL.Path, body)

			rec, replay, err := store.Begin(r.Context(), idemKey, reqHash)
			switch {
			case err == idempotency.ErrKeyReuse:
				writeError(w, http.StatusUnprocessableEntity, "idempotency_key_reuse", "key already used with a different request")
				return
			case err == idempotency.ErrInFlight:
				writeError(w, http.StatusConflict, "request_in_flight", "an identical request is being processed")
				return
			case err != nil:
				log.ErrorContext(r.Context(), "idempotency begin failed", slog.Any("err", err))
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
				return
			case replay:
				// Replay the stored response verbatim.
				for k, v := range rec.Headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("Idempotent-Replay", "true")
				w.WriteHeader(rec.Status)
				_, _ = w.Write(rec.Body)
				return
			}

			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)

			// Persist only successful results; on failure, release the lock so
			// the client can retry safely (no poisoned idempotency key).
			if cw.status >= 200 && cw.status < 300 {
				if err := store.Complete(r.Context(), idemKey, idempotency.Record{
					Status:      cw.status,
					Body:        cw.buf.Bytes(),
					Headers:     map[string]string{"Content-Type": cw.Header().Get("Content-Type")},
					RequestHash: reqHash,
				}); err != nil {
					log.ErrorContext(r.Context(), "idempotency complete failed", slog.Any("err", err))
				}
			} else {
				if err := store.Abort(r.Context(), idemKey); err != nil {
					log.ErrorContext(r.Context(), "idempotency abort failed", slog.Any("err", err))
				}
			}
		})
	}
}
