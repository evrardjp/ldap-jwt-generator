package jwt

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/user"
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
	claims := AuthJWTClaims{
		// Custom claims
		Username: userDetails.Username,
		Email:    userDetails.Email,
		UserDN:   userDetails.UserDN,
		TenantID: tenantID,
		Groups:   userDetails.Groups,

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

//func (issuer *TokenIssuer) GenerateJWT_OLD(w http.ResponseWriter, r *http.Request) {
//
//	userContext := r.Context().Value(handlers.UserContextKey)
//	if userContext == nil {
//		slog.Error("No user found in the context")
//		w.WriteHeader(http.StatusUnauthorized)
//		return
//	}
//	user := userContext.(types.User)
//	scopes := r.URL.Query().Get("scopes")
//
//	token, err := issuer.createAccessToken(user, scopes)
//
//	if err != nil {
//		TokenCounter.WithLabelValues("token_error").Inc()
//		slog.Error("granting token fail for user", "user", user.Username, "error", err)
//		w.WriteHeader(http.StatusUnauthorized)
//		return
//	}
//
//	slog.Debug("token generated", "user", user.Username, "scopes", scopes)
//	KubiTokenSizeHistogram.Observe(float64(len(*token)))
//	w.WriteHeader(http.StatusCreated)
//	io.WriteString(w, *token)
//}

// Generate an service token from a user account
// The semantic of this token is held by the target backend, ex: service api, promotion api...
// Only users with "transverse" access can generate extra tokens
//func (issuer *TokenIssuer) generateServiceJWTClaims(username string, email string, scopes string) (types.AuthJWTClaims, error) {
//
//	expiration := time.Now().Add(issuer.ExtraTokenDuration)
//
//	// Create the Claims
//	claims := types.AuthJWTClaims{
//		Auths:    []*types.Project{},
//		User:     username,
//		Contact:  email,
//		Locator:  issuer.Locator,
//		Endpoint: issuer.PublicApiServerURL.Host,
//		Tenant:   issuer.Tenant,
//		Scopes:   scopes,
//		StandardClaims: jwt.StandardClaims{
//			ExpiresAt: expiration.Unix(),
//			Issuer:    "Kubi Server",
//		},
//	}
//
//	return claims, nil
//}
//
//// Generate a user token from a user account
//// TODO evrardjp: Pass User as parameters.
//func (issuer *TokenIssuer) generateUserJWTClaims(auths []*types.Project, groups []string, username string, email string, hasAdminAccess bool, hasApplicationAccess bool, hasOpsAccess bool, hasViewerAccess bool, hasServiceAccess bool) (types.AuthJWTClaims, error) {
//
//	if hasAdminAccess || hasApplicationAccess || hasOpsAccess || hasServiceAccess {
//		slog.Debug("user will have transversal access, removing all the projects", "user", username, "admin", hasAdminAccess, "application", hasApplicationAccess, "ops", hasOpsAccess, "service", hasServiceAccess)
//		// To be removed when ppl will have the right to have both transversal and project access
//		// Currently removed because too many groups.
//		auths = []*types.Project{}
//	} else {
//		slog.Debug("user will have access to the projects", "user", username, "projects", fmt.Sprint(auths))
//	}
//
//	var expirationTime time.Time
//
//	if hasServiceAccess {
//		slog.Debug("The user will have an extra token duration", "user", username, "duration", issuer.ExtraTokenDuration)
//		expirationTime = time.Now().Add(issuer.ExtraTokenDuration)
//	} else {
//		expirationTime = time.Now().Add(issuer.TokenDuration)
//	}
//
//	// Create the Claims
//	claims := types.AuthJWTClaims{
//		Auths:             auths,
//		User:              username,
//		Groups:            groups,
//		Contact:           email,
//		AdminAccess:       hasAdminAccess,
//		ApplicationAccess: hasApplicationAccess,
//		OpsAccess:         hasOpsAccess,
//		ServiceAccess:     hasServiceAccess,
//		ViewerAccess:      hasViewerAccess,
//		Locator:           issuer.Locator,
//		Endpoint:          issuer.PublicApiServerURL.Host,
//		Tenant:            issuer.Tenant,
//
//		StandardClaims: jwt.StandardClaims{
//			ExpiresAt: expirationTime.Unix(),
//			Issuer:    "Kubi Server",
//		},
//	}
//
//	return claims, nil
//}
//
//func (issuer *TokenIssuer) signJWTClaims(claims types.AuthJWTClaims) (*string, error) {
//	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
//	if issuer.EcdsaPrivate == nil {
//		return nil, fmt.Errorf("the private key is nil") // should not happen, avoid panic.
//	}
//	signedToken, err := token.SignedString(issuer.EcdsaPrivate)
//	if err != nil {
//		return nil, err
//	}
//	return &signedToken, err
//}
//
//func (issuer *TokenIssuer) createAccessToken(user types.User, scopes string) (*string, error) {
//
//	var claims types.AuthJWTClaims
//	var err error
//	var token *string = nil
//
//	if len(scopes) > 0 {
//		if !(user.IsAdmin || user.IsAppOps || user.IsCloudOps) {
//			return nil, fmt.Errorf("the user %s cannot generate extra token with no transversal access (admin: %v, application: %v, ops: %v)", user.Username, user.IsAdmin, user.IsAppOps, user.IsCloudOps)
//		}
//		claims, err = issuer.generateServiceJWTClaims(user.Username, user.Email, scopes)
//		if err != nil {
//			return nil, fmt.Errorf("unable to generate the token %v", err)
//		}
//	} else {
//		// Do not pass the full group list, as they wont parse as Projects.
//		// When the Project Access will be removed, the createAccessToken will become a simple wrapper around generateUserJWTClaims and their signature.
//		// We can then use Factory or Strategy pattern to clean up the code further.
//		projects := project.GetProjectsFromGrouplist(user.ProjectAccesses)
//
//		claims, err = issuer.generateUserJWTClaims(projects, user.Groups, user.Username, user.Email, user.IsAdmin, user.IsAppOps, user.IsCloudOps, user.IsViewer, user.IsService)
//		if err != nil {
//			return nil, fmt.Errorf("unable to generate the token %v", err)
//		}
//	}
//
//	token, err = issuer.signJWTClaims(claims)
//	if err != nil {
//		return nil, fmt.Errorf("unable to sign the token %v", err)
//	}
//
//	if token == nil {
//		return nil, fmt.Errorf("the token is nil")
//	}
//	TokenCounter.WithLabelValues("token_success").Inc()
//	return token, nil
//}
//
//
//func (issuer *TokenIssuer) VerifyToken(usertoken string) (*types.AuthJWTClaims, error) {
//
//	// this verifies the token and its signature
//	token, err := jwt.ParseWithClaims(usertoken, &types.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
//		if issuer.EcdsaPublic == nil {
//			return nil, fmt.Errorf("the public key is nil")
//		}
//		return issuer.EcdsaPublic, nil
//	})
//	if err != nil {
//		slog.Info("Bad token", "error", err.Error())
//		return nil, err
//	}
//
//	if claims, ok := token.Claims.(*types.AuthJWTClaims); ok && token.Valid {
//		return claims, nil
//	} else {
//		slog.Info("Auth token is invalid")
//		return nil, err
//	}
//}
