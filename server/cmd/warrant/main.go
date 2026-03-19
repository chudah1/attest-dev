package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/warrant-dev/warrant/internal/audit"
	"github.com/warrant-dev/warrant/internal/revocation"
	"github.com/warrant-dev/warrant/internal/token"
)

type config struct {
	Port           string
	DatabaseURL    string
	IssuerURI      string
	PrivateKeyPath string
}

func configFromEnv() config {
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	return config{
		Port:           get("PORT", "8080"),
		DatabaseURL:    get("DATABASE_URL", ""),
		IssuerURI:      get("ISSUER_URI", "https://warrant.dev"),
		PrivateKeyPath: get("PRIVATE_KEY_PATH", ""),
	}
}

func loadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		slog.Warn("PRIVATE_KEY_PATH not set — generating ephemeral RSA-2048 key (dev mode)")
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := configFromEnv()

	privateKey, err := loadOrGenerateKey(cfg.PrivateKeyPath)
	if err != nil {
		slog.Error("failed to load private key", "err", err)
		os.Exit(1)
	}

	// Wire storage backends: Postgres when DATABASE_URL is set, in-memory otherwise.
	var (
		revStore revocation.Revoker
		auditLog audit.Logger
	)

	if cfg.DatabaseURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			slog.Error("failed to connect to database", "err", err)
			os.Exit(1)
		}
		defer pool.Close()

		slog.Info("storage: postgres", "url", cfg.DatabaseURL)
		revStore = revocation.NewStore(pool)
		auditLog = audit.NewLog(pool)
	} else {
		slog.Warn("DATABASE_URL not set — using in-memory storage (dev mode, data lost on restart)")
		revStore = revocation.NewMemoryStore()
		auditLog = audit.NewMemoryLog()
	}

	iss := token.NewIssuer(privateKey, cfg.IssuerURI)

	h := &handlers{
		issuer:   iss,
		pubKey:   &privateKey.PublicKey,
		revStore: revStore,
		auditLog: auditLog,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(jsonLogger)

	r.Get("/health", h.health)
	r.Get("/.well-known/jwks.json", h.jwks)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/credentials", h.issueCredential)
		r.Post("/credentials/delegate", h.delegateCredential)
		r.Delete("/credentials/{jti}", h.revokeCredential)
		r.Get("/revoked/{jti}", h.checkRevocation)
		r.Get("/tasks/{tid}/audit", h.getAuditLog)
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		slog.Info("shutdown signal received", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "err", err)
		}
		close(done)
	}()

	slog.Info("server starting", "port", cfg.Port, "issuer", cfg.IssuerURI)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	<-done
	slog.Info("server stopped")
}

// jsonLogger is a chi middleware that emits structured JSON request logs.
func jsonLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}
