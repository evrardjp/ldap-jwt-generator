package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"ldap-jwt-generator/internal/ldap"
)

type tenantContextKey string

const TenantIDKey tenantContextKey = "tenantID"
const TenantAuthenticatorKey tenantContextKey = "tenantAuthenticator"

// WithTenantConfig extracts Tenant-Id header and looks up authenticator in registry
func WithTenantConfig(registry ldap.TenantRegistryInterface, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Tenant-Id header
		tenantID := r.Header.Get("Tenant-Id")
		if tenantID == "" {
			slog.Info("missing Tenant-Id header")
			http.Error(w, "Bad Request: Tenant-Id header is required", http.StatusBadRequest)
			return
		}

		// Lookup tenant authenticator in registry (O(1) map lookup)
		authenticator, err := registry.GetAuthenticator(tenantID)
		if err != nil {
			slog.Info("invalid tenant", "tenant", tenantID, "error", err)
			http.Error(w, "Bad Request: Unknown tenant", http.StatusBadRequest)
			return
		}

		// Store authenticator and tenant ID in context
		ctx := context.WithValue(r.Context(), TenantAuthenticatorKey, authenticator)
		ctx = context.WithValue(ctx, TenantIDKey, tenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
