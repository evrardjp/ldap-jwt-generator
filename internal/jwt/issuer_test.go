package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/user"
)

// Test helper to create a TokenIssuer with test keys
func createTestTokenIssuer(t *testing.T) *TokenIssuer {
	t.Helper()

	// Load test keys
	privateKeyPEM, err := os.ReadFile("../../test/ecdsa-key.pem")
	if err != nil {
		t.Fatalf("Failed to read test private key: %v", err)
	}

	publicKeyPEM, err := os.ReadFile("../../test/ecdsa-pub.pem")
	if err != nil {
		t.Fatalf("Failed to read test public key: %v", err)
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	duration, _ := time.ParseDuration("4h")

	return &TokenIssuer{
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		TokenDuration: duration,
		IssuerFQDN:    "ldap-jwt-generator.example.com",
	}
}

// Test helper to create context with user and tenant
func createContextWithUserAndTenant(userDetails *user.Details, tenantID string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, handlers.UserContextKey, userDetails)
	ctx = context.WithValue(ctx, handlers.TenantIDKey, tenantID)
	return ctx
}

func TestGenerateJWT_AdminUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Create admin user (member of admin group)
	userDetails := &user.Details{
		Username: "admin-user",
		Email:    "admin@example.com",
		UserDN:   "CN=Admin User,OU=Users,DC=example,DC=org",
		Groups:   []string{"ADMIN_KUBERNETES", "ALL_USERS"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	// Verify HTTP response
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	if tokenString == "" {
		t.Fatal("Expected token in response body, got empty string")
	}

	// Parse and verify token
	token, err := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return issuer.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("Token is not valid")
	}

	claims, ok := token.Claims.(*AuthJWTClaims)
	if !ok {
		t.Fatal("Failed to cast claims to AuthJWTClaims")
	}

	// Verify custom claims
	if claims.Username != "admin-user" {
		t.Errorf("Expected username 'admin-user', got '%s'", claims.Username)
	}
	if claims.Email != "admin@example.com" {
		t.Errorf("Expected email 'admin@example.com', got '%s'", claims.Email)
	}
	if claims.UserDN != "CN=Admin User,OU=Users,DC=example,DC=org" {
		t.Errorf("Expected userDN 'CN=Admin User,OU=Users,DC=example,DC=org', got '%s'", claims.UserDN)
	}
	if claims.TenantID != "tenant1" {
		t.Errorf("Expected tenantID 'tenant1', got '%s'", claims.TenantID)
	}
	if len(claims.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(claims.Groups))
	}
	if !contains(claims.Groups, "ADMIN_KUBERNETES") {
		t.Error("Expected groups to contain 'ADMIN_KUBERNETES'")
	}

	// Verify standard JWT claims
	if claims.Issuer != "ldap-jwt-generator.example.com" {
		t.Errorf("Expected issuer 'ldap-jwt-generator.example.com', got '%s'", claims.Issuer)
	}
	if claims.Subject != "admin-user" {
		t.Errorf("Expected subject 'admin-user', got '%s'", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "ldap-jwt-generator.example.com" {
		t.Errorf("Expected audience ['ldap-jwt-generator.example.com'], got %v", claims.Audience)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.Before(time.Now()) {
		t.Error("Token should have valid expiration in the future")
	}
	if claims.NotBefore == nil || claims.NotBefore.Time.After(time.Now().Add(time.Minute)) {
		t.Error("Token nbf should be now or in the past")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.Time.After(time.Now().Add(time.Minute)) {
		t.Error("Token iat should be now or in the past")
	}
	if claims.ID == "" {
		t.Error("Token should have a JTI (JWT ID)")
	}
	if !strings.HasPrefix(claims.ID, "admin-user-") {
		t.Errorf("Expected JTI to start with 'admin-user-', got '%s'", claims.ID)
	}
}

func TestGenerateJWT_CustomerOpsUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Create customer ops user (member of customer ops group)
	userDetails := &user.Details{
		Username: "customerops-user",
		Email:    "customerops@example.com",
		UserDN:   "CN=Customer Ops User,OU=Users,DC=example,DC=org",
		Groups:   []string{"CUSTOMER_OPS", "PROJECT_TEAM_A"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant2")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, err := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims := token.Claims.(*AuthJWTClaims)

	if claims.Username != "customerops-user" {
		t.Errorf("Expected username 'customerops-user', got '%s'", claims.Username)
	}
	if claims.TenantID != "tenant2" {
		t.Errorf("Expected tenantID 'tenant2', got '%s'", claims.TenantID)
	}
	if !contains(claims.Groups, "CUSTOMER_OPS") {
		t.Error("Expected groups to contain 'CUSTOMER_OPS'")
	}
	if !contains(claims.Groups, "PROJECT_TEAM_A") {
		t.Error("Expected groups to contain 'PROJECT_TEAM_A'")
	}
}

func TestGenerateJWT_AppOpsUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "appops-user",
		Email:    "appops@example.com",
		UserDN:   "CN=App Ops User,OU=Users,DC=example,DC=org",
		Groups:   []string{"APPLICATION_OPS", "DEVELOPERS"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	if !contains(claims.Groups, "APPLICATION_OPS") {
		t.Error("Expected groups to contain 'APPLICATION_OPS'")
	}
}

func TestGenerateJWT_ViewerUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "viewer-user",
		Email:    "viewer@example.com",
		UserDN:   "CN=Viewer User,OU=Users,DC=example,DC=org",
		Groups:   []string{"CLUSTER_VIEWER"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	if !contains(claims.Groups, "CLUSTER_VIEWER") {
		t.Error("Expected groups to contain 'CLUSTER_VIEWER'")
	}
}

func TestGenerateJWT_ServiceAccountUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "service-account",
		Email:    "service@example.com",
		UserDN:   "CN=Service Account,OU=ServiceAccounts,DC=example,DC=org",
		Groups:   []string{"SERVICE_ACCOUNTS", "AUTOMATED_PROCESSES"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	if !contains(claims.Groups, "SERVICE_ACCOUNTS") {
		t.Error("Expected groups to contain 'SERVICE_ACCOUNTS'")
	}
	if !contains(claims.Groups, "AUTOMATED_PROCESSES") {
		t.Error("Expected groups to contain 'AUTOMATED_PROCESSES'")
	}
}

func TestGenerateJWT_RegularUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "regular-user",
		Email:    "regular@example.com",
		UserDN:   "CN=Regular User,OU=Users,DC=example,DC=org",
		Groups:   []string{"PROJECT_ALPHA", "PROJECT_BETA"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	if len(claims.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(claims.Groups))
	}
}

func TestGenerateJWT_UserWithNoGroups(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "no-groups-user",
		Email:    "nogroups@example.com",
		UserDN:   "CN=No Groups User,OU=Users,DC=example,DC=org",
		Groups:   []string{},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	// Should still succeed and generate token with empty groups
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	if len(claims.Groups) != 0 {
		t.Errorf("Expected 0 groups, got %d", len(claims.Groups))
	}
}

func TestGenerateJWT_MissingUserContext(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Context without user
	ctx := context.WithValue(context.Background(), handlers.TenantIDKey, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestGenerateJWT_MissingTenantContext(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "test-user",
		Email:    "test@example.com",
		UserDN:   "CN=Test User,DC=example,DC=org",
		Groups:   []string{"TEST_GROUP"},
	}

	// Context without tenant
	ctx := context.WithValue(context.Background(), handlers.UserContextKey, userDetails)
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestGenerateJWT_TokenExpiration(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "test-user",
		Email:    "test@example.com",
		UserDN:   "CN=Test User,DC=example,DC=org",
		Groups:   []string{},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	beforeGeneration := time.Now()
	issuer.GenerateJWT(w, req)
	afterGeneration := time.Now()

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)

	// Verify expiration is approximately 4 hours from now
	expectedExpiry := beforeGeneration.Add(4 * time.Hour)
	if claims.ExpiresAt.Time.Before(expectedExpiry.Add(-time.Minute)) || claims.ExpiresAt.Time.After(afterGeneration.Add(4*time.Hour).Add(time.Minute)) {
		t.Errorf("Token expiration not within expected range. Expected around %v, got %v", expectedExpiry, claims.ExpiresAt.Time)
	}

	// Verify issued at is recent
	if claims.IssuedAt.Time.Before(beforeGeneration.Add(-time.Second)) || claims.IssuedAt.Time.After(afterGeneration.Add(time.Second)) {
		t.Errorf("Token iat not within expected range. Expected between %v and %v, got %v", beforeGeneration, afterGeneration, claims.IssuedAt.Time)
	}

	// Verify not before is recent
	if claims.NotBefore.Time.Before(beforeGeneration.Add(-time.Second)) || claims.NotBefore.Time.After(afterGeneration.Add(time.Second)) {
		t.Errorf("Token nbf not within expected range. Expected between %v and %v, got %v", beforeGeneration, afterGeneration, claims.NotBefore.Time)
	}
}

func TestGenerateJWT_JTIUniqueness(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Username: "test-user",
		Email:    "test@example.com",
		UserDN:   "CN=Test User,DC=example,DC=org",
		Groups:   []string{},
	}

	// Generate multiple tokens and verify JTIs are unique
	jtis := make(map[string]bool)

	for i := 0; i < 5; i++ {
		ctx := createContextWithUserAndTenant(userDetails, "tenant1")
		req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		issuer.GenerateJWT(w, req)

		tokenString := w.Body.String()
		token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return issuer.PublicKey, nil
		})

		claims := token.Claims.(*AuthJWTClaims)

		if jtis[claims.ID] {
			t.Errorf("JTI %s is not unique!", claims.ID)
		}
		jtis[claims.ID] = true

		// Small delay to ensure different timestamps
		time.Sleep(time.Second)
	}

	if len(jtis) != 5 {
		t.Errorf("Expected 5 unique JTIs, got %d", len(jtis))
	}
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
