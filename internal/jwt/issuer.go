package jwt

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/user"

	"github.com/golang-jwt/jwt/v5"
)

func (issuer *TokenIssuer) GenerateJWT(w http.ResponseWriter, r *http.Request) {
	// Extract user from context
	userValue := r.Context().Value(handlers.UserContextKey)
	if userValue == nil {
		slog.Error("no user found in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userDetails := userValue.(*user.Details)

	// Extract tenant ID from context
	tenantIDValue := r.Context().Value(handlers.TenantIDKey)
	if tenantIDValue == nil {
		slog.Error("no tenant ID found in context")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	tenantID := tenantIDValue.(string)

	now := time.Now()
	expiresAt := now.Add(issuer.TokenDuration)

	// Create JWT claims with all required fields and proper security
	// Incorrect tenantID, Username, Groups must have been caught earlier in middlewares (see also e2e testing).
	claims := AuthJWTClaims{
		// Custom claims
		User:    userDetails.Username,
		Contact: userDetails.Email,
		UserDN:  userDetails.UserDN,
		Tenant:  tenantID,
		Groups:  userDetails.Groups,

		// Standard JWT claims for security
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer.IssuerFQDN,                      // iss: Application FQDN from env var
			Subject:   userDetails.Username,                   // sub: User identity
			Audience:  jwt.ClaimStrings{issuer.IssuerFQDN},    // aud: Intended audience (same as issuer)
			ExpiresAt: jwt.NewNumericDate(expiresAt),          // exp: Expiration time
			NotBefore: jwt.NewNumericDate(now),                // nbf: Not valid before (now)
			IssuedAt:  jwt.NewNumericDate(now),                // iat: Issued at time
			ID:        generateJTI(userDetails.Username, now), // jti: Unique token ID
		},
	}

	// Create and sign token with ECDSA-P512
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	signedToken, err := token.SignedString(issuer.PrivateKey)
	if err != nil {
		TokenCounter.WithLabelValues("token_error").Inc()
		slog.Error("failed to sign token", "user", userDetails.Username, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Record metrics
	TokenCounter.WithLabelValues("token_success").Inc()
	KubiTokenSizeHistogram.Observe(float64(len(signedToken)))

	slog.Debug("token generated",
		"user", userDetails.Username,
		"tenant", tenantID,
		"groupCount", len(userDetails.Groups),
		"expiresAt", expiresAt)

	// Return token
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, signedToken)
}

// generateJTI creates a unique token identifier
func generateJTI(username string, issuedAt time.Time) string {
	return fmt.Sprintf("%s-%d", username, issuedAt.Unix())
}
