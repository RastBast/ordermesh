// Package httpserver provides a graceful HTTP server wrapper.
package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/RastBast/ordermesh-/internal/config"
)

// Server wraps http.Server with graceful shutdown.
type Server struct {
	srv *http.Server
	log *slog.Logger
	cfg config.HTTPConfig
}

// New constructs the server for the given handler.
func New(cfg config.HTTPConfig, handler http.Handler, log *slog.Logger) *Server {
	return &Server{
		srv: &http.Server{
			Addr:         cfg.Addr,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
		log: log,
		cfg: cfg,
	}
}

// Start runs the server until ctx is cancelled, then gracefully shuts down.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening", slog.String("addr", s.cfg.Addr))
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		s.log.Info("http server shutting down")
		return s.srv.Shutdown(shutdownCtx)
	}
}
