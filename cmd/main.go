package main

import (
	"fmt"
	"net/http"
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/jwt"
	"ldap-jwt-generator/internal/ldap"
)

const listeningPort = 8080

func main() {
	// Setup structured JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Initialize LDAP base configuration (connection params)
	ldapBaseConfig, err := ldap.NewLDAPBaseConfig()
	if err != nil {
		slog.Error("cannot initialize LDAP base config", "error", err)
		os.Exit(1)
	}

	// Load all tenant configurations at startup (fail-fast validation)
	tenantRegistry, err := ldap.NewTenantRegistry(ldapBaseConfig)
	if err != nil {
		slog.Error("cannot initialize tenant registry", "error", err)
		os.Exit(1)
	}

	// Initialize JWT token issuer (includes loading JWT_ISSUER_FQDN)
	tokenIssuer, err := jwt.NewTokenIssuer()
	if err != nil {
		slog.Error("unable to create token issuer", "error", err)
		os.Exit(1)
	}

	// Setup HTTP routing (using Go 1.22+ patterns with method prefixes)
	mux := http.NewServeMux()

	// /token endpoint with middleware chain:
	// 1. WithTenantConfig: Extract and validate Tenant-Id header (lookup in registry)
	// 2. WithBasicAuth: Authenticate user via LDAP with tenant config
	// 3. WithAuthorization: Fetch user groups from LDAP
	// 4. GenerateJWT: Create and return signed JWT token
	mux.HandleFunc("GET /token",
		handlers.WithTenantConfig(tenantRegistry,
			handlers.WithBasicAuth(
				handlers.WithAuthorization(
					tokenIssuer.GenerateJWT))))

	// /metrics endpoint for Prometheus monitoring
	mux.Handle("GET /metrics", promhttp.Handler())

	// Wrap entire mux with Prometheus metrics middleware
	httpHandler := handlers.Prometheus(mux)

	// Start HTTP server
	slog.Info("starting server", "port", listeningPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", listeningPort), httpHandler); err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(2)
	}
}
