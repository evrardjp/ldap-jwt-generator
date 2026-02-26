package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

func WithBasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract tenant authenticator from context (set by WithTenantConfig)
		authValue := r.Context().Value(TenantAuthenticatorKey)
		if authValue == nil {
			slog.Error("tenant authenticator not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		authenticator := authValue.(Authenticator)

		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		username, password, ok := r.BasicAuth()
		if ok {
			if len(username) == 0 || len(password) == 0 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			user, err := authenticator.AuthN(username, password)
			if err != nil {
				slog.Info(fmt.Sprintf("user %v failed to authenticate, %v", username, err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user) // Store the user pointer in the context
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
