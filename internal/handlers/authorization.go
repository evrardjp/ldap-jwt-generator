package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"ldap-jwt-generator/internal/user"
)

func WithGroupEnrichment(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract user from context (set by WithBasicAuth)
		userValue := r.Context().Value(UserContextKey)
		if userValue == nil {
			slog.Error("user not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		userDetails := userValue.(*user.Details)

		// Extract tenant authenticator from context
		authValue := r.Context().Value(TenantAuthenticatorKey)
		if authValue == nil {
			slog.Error("tenant authenticator not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		authenticator := authValue.(Authorizer)

		// Fetch user groups using tenant-specific configuration
		enrichedUser, err := authenticator.AuthZ(userDetails)
		if err != nil {
			slog.Error("failed to fetch user groups", "user", userDetails.Username, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Verify user belongs to at least one group (authorization requirement)
		if len(enrichedUser.Groups) == 0 {
			slog.Warn("user has no groups, denying access",
				"user", enrichedUser.Username,
				"userDN", enrichedUser.UserDN)
			http.Error(w, "Forbidden: User must belong to at least one group", http.StatusForbidden)
			return
		}

		// Update context with enriched user
		ctx := context.WithValue(r.Context(), UserContextKey, enrichedUser)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
