package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/user"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testFQDN = "ldap-jwt-generator.example.com"
)

// Test helper to create a TokenIssuer with test keys
func createTestTokenIssuer(t *testing.T) *TokenIssuer {
	t.Helper()

	// Load test keys
	privateKeyPEM, err := os.ReadFile("../../test/fixtures/signing-keys/ecdsa-private-key.pem")
	if err != nil {
		t.Fatalf("Failed to read test private key: %v", err)
	}

	publicKeyPEM, err := os.ReadFile("../../test/fixtures/signing-keys/ecdsa-public-key.pem")
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
		IssuerFQDN:    testFQDN,
	}
}

// Test helper to create context with user and tenant
func createContextWithUserAndTenant(userDetails *user.Details, tenantID string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, handlers.UserContextKey, userDetails)
	ctx = context.WithValue(ctx, handlers.TenantIDKey, tenantID)
	return ctx
}

func TestGenerateJWT_User(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Create admin user (member of admin group)
	userDetails := &user.Details{
		Name:   "admin-user",
		Email:  "admin@example.com",
		DN:     "CN=Admin Name,OU=Users,DC=example,DC=org",
		Groups: []string{"ADMIN_KUBERNETES", "ALL_USERS"},
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
	if claims.User != "admin-user" {
		t.Errorf("Expected username 'admin-user', got '%s'", claims.User)
	}
	if claims.Contact != "admin@example.com" {
		t.Errorf("Expected email 'admin@example.com', got '%s'", claims.Contact)
	}
	if claims.UserDN != "CN=Admin Name,OU=Users,DC=example,DC=org" {
		t.Errorf("Expected userDN 'CN=Admin Name,OU=Users,DC=example,DC=org', got '%s'", claims.UserDN)
	}
	if claims.Tenant != "tenant1" {
		t.Errorf("Expected tenantID 'tenant1', got '%s'", claims.Tenant)
	}
	if len(claims.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(claims.Groups))
	}
	if !slices.Contains(claims.Groups, "ADMIN_KUBERNETES") {
		t.Error("Expected groups to contain 'ADMIN_KUBERNETES'")
	}

	// Verify standard JWT claims
	if claims.Issuer != "ldap-jwt-generator.example.com" {
		t.Errorf("Expected issuer 'ldap-jwt-generator.example.com', got '%s'", claims.Issuer)
	}
	if claims.Subject != "admin-user" {
		t.Errorf("Expected subject 'admin-user', got '%s'", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != testFQDN {
		t.Errorf("Expected audience ['ldap-jwt-generator.example.com'], got %v", claims.Audience)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		t.Error("Token should have valid expiration in the future")
	}
	if claims.NotBefore == nil || claims.NotBefore.After(time.Now().Add(time.Minute)) {
		t.Error("Token nbf should be now or in the past")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.After(time.Now().Add(time.Minute)) {
		t.Error("Token iat should be now or in the past")
	}
	if claims.ID == "" {
		t.Error("Token should have a JTI (JWT ID)")
	}
	if !strings.HasPrefix(claims.ID, "admin-user-") {
		t.Errorf("Expected JTI to start with 'admin-user-', got '%s'", claims.ID)
	}
}

// TestGenerateJWT_EmptyUser is a test to ensure that the system can write proper token even without user.
// It's a "technically correct" test. Yet, we should never arrive to this case in real life.
func TestGenerateJWT_EmptyUser(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	// Should still succeed and generate token with empty token
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims := token.Claims.(*AuthJWTClaims)
	// Verify standard JWT claims
	if claims.Issuer != testFQDN {
		t.Errorf("Expected issuer %s, got '%s'", testFQDN, claims.Issuer)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != testFQDN {
		t.Errorf("Expected audience ['ldap-jwt-generator.example.com'], got %v", claims.Audience)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		t.Error("Token should have valid expiration in the future")
	}
	if claims.NotBefore == nil || claims.NotBefore.After(time.Now().Add(time.Minute)) {
		t.Error("Token nbf should be now or in the past")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.After(time.Now().Add(time.Minute)) {
		t.Error("Token iat should be now or in the past")
	}
	if claims.ID == "" {
		t.Error("Token should have a JTI (JWT ID)")
	}
	if !strings.HasPrefix(claims.ID, "-") {
		t.Errorf("Expected JTI to start with '-' for empty username, got '%s'", claims.ID)
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
		Name:   "test-user",
		Email:  "test@example.com",
		DN:     "CN=Test Name,DC=example,DC=org",
		Groups: []string{"TEST_GROUP"},
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
		Name:   "test-user",
		Email:  "test@example.com",
		DN:     "CN=Test Name,DC=example,DC=org",
		Groups: []string{},
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
	if claims.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || claims.ExpiresAt.After(afterGeneration.Add(4*time.Hour).Add(time.Minute)) {
		t.Errorf("Token expiration not within expected range. Expected around %v, got %v", expectedExpiry, claims.ExpiresAt)
	}

	// Verify issued at is recent
	if claims.IssuedAt.Before(beforeGeneration.Add(-time.Second)) || claims.IssuedAt.After(afterGeneration.Add(time.Second)) {
		t.Errorf("Token iat not within expected range. Expected between %v and %v, got %v", beforeGeneration, afterGeneration, claims.IssuedAt)
	}

	// Verify not before is recent
	if claims.NotBefore.Before(beforeGeneration.Add(-time.Second)) || claims.NotBefore.After(afterGeneration.Add(time.Second)) {
		t.Errorf("Token nbf not within expected range. Expected between %v and %v, got %v", beforeGeneration, afterGeneration, claims.NotBefore)
	}
}

func TestGenerateJWT_JTIUniqueness(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Name:   "test-user",
		Email:  "test@example.com",
		DN:     "CN=Test Name,DC=example,DC=org",
		Groups: []string{},
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

func TestGenerateJWT_MultipleGroupsPreservation(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Create user with 6 groups to verify no truncation
	userDetails := &user.Details{
		Name:  "multi-group-user",
		Email: "user@example.com",
		DN:    "CN=Multi Group User,OU=Users,DC=example,DC=org",
		Groups: []string{
			"GROUP_1",
			"GROUP_2",
			"GROUP_3",
			"GROUP_4",
			"GROUP_5",
			"GROUP_6",
		},
	}

	ctx := createContextWithUserAndTenant(userDetails, "tenant1")
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

	// Verify all 6 groups are present
	if len(claims.Groups) != 6 {
		t.Errorf("Expected 6 groups, got %d", len(claims.Groups))
	}

	// Verify each group is present (order preserved)
	for i, expectedGroup := range userDetails.Groups {
		if i >= len(claims.Groups) {
			t.Errorf("Expected group '%s' at index %d, but groups slice is too short", expectedGroup, i)
			continue
		}
		if claims.Groups[i] != expectedGroup {
			t.Errorf("Expected group '%s' at index %d, got '%s'", expectedGroup, i, claims.Groups[i])
		}
	}
}

func TestGenerateJWT_TenantIsolation(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	// Same user for both requests
	userDetails := &user.Details{
		Name:   "shared-user",
		Email:  "user@example.com",
		DN:     "CN=Shared User,OU=Users,DC=example,DC=org",
		Groups: []string{"SHARED_GROUP"},
	}

	// Generate token for tenant1
	ctx1 := createContextWithUserAndTenant(userDetails, "tenant1")
	req1 := httptest.NewRequest("GET", "/token", nil).WithContext(ctx1)
	w1 := httptest.NewRecorder()
	issuer.GenerateJWT(w1, req1)

	// Generate token for tenant2
	ctx2 := createContextWithUserAndTenant(userDetails, "tenant2")
	req2 := httptest.NewRequest("GET", "/token", nil).WithContext(ctx2)
	w2 := httptest.NewRecorder()
	issuer.GenerateJWT(w2, req2)

	// Parse both tokens
	token1, _ := jwt.ParseWithClaims(w1.Body.String(), &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})
	token2, _ := jwt.ParseWithClaims(w2.Body.String(), &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})

	claims1 := token1.Claims.(*AuthJWTClaims)
	claims2 := token2.Claims.(*AuthJWTClaims)

	// Verify tenant claims are different
	if claims1.Tenant != "tenant1" {
		t.Errorf("Expected tenant1, got '%s'", claims1.Tenant)
	}
	if claims2.Tenant != "tenant2" {
		t.Errorf("Expected tenant2, got '%s'", claims2.Tenant)
	}

	// Verify the tokens themselves are different (different tenant = different token)
	if w1.Body.String() == w2.Body.String() {
		t.Error("Expected different tokens for different tenants, but they are identical")
	}

	// Verify same user claims in both
	if claims1.User != claims2.User {
		t.Error("Expected same user in both tokens")
	}
	if claims1.Contact != claims2.Contact {
		t.Error("Expected same email in both tokens")
	}
}

func TestGenerateJWT_AllClaimFieldsPopulated(t *testing.T) {
	issuer := createTestTokenIssuer(t)

	userDetails := &user.Details{
		Name:   "complete-user",
		Email:  "complete@example.com",
		DN:     "CN=Complete User,OU=Users,DC=example,DC=org",
		Groups: []string{"GROUP_A", "GROUP_B"},
	}

	ctx := createContextWithUserAndTenant(userDetails, "production")
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	issuer.GenerateJWT(w, req)

	tokenString := w.Body.String()
	token, _ := jwt.ParseWithClaims(tokenString, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.PublicKey, nil
	})
	claims := token.Claims.(*AuthJWTClaims)

	// Verify ALL custom claims are populated
	if claims.User == "" {
		t.Error("User claim is empty")
	}
	if claims.Contact == "" {
		t.Error("Contact (email) claim is empty")
	}
	if claims.UserDN == "" {
		t.Error("UserDN claim is empty")
	}
	if claims.Tenant == "" {
		t.Error("Tenant claim is empty")
	}
	if len(claims.Groups) == 0 {
		t.Error("Groups claim is empty")
	}

	// Verify ALL standard JWT claims are populated
	if claims.Issuer == "" {
		t.Error("Issuer (iss) claim is empty")
	}
	if claims.Subject == "" {
		t.Error("Subject (sub) claim is empty")
	}
	if len(claims.Audience) == 0 {
		t.Error("Audience (aud) claim is empty")
	}
	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt (exp) claim is nil")
	}
	if claims.NotBefore == nil {
		t.Error("NotBefore (nbf) claim is nil")
	}
	if claims.IssuedAt == nil {
		t.Error("IssuedAt (iat) claim is nil")
	}
	if claims.ID == "" {
		t.Error("ID (jti) claim is empty")
	}

	// Verify specific values match input
	if claims.User != "complete-user" {
		t.Errorf("Expected user 'complete-user', got '%s'", claims.User)
	}
	if claims.Contact != "complete@example.com" {
		t.Errorf("Expected email 'complete@example.com', got '%s'", claims.Contact)
	}
	if claims.Tenant != "production" {
		t.Errorf("Expected tenant 'production', got '%s'", claims.Tenant)
	}
}

// This need extending with:
// Tests for gibberish tokens
// Tests for invalid chars in token
func Test_generateJTI(t *testing.T) {
	type args struct {
		username string
		issuedAt time.Time
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty username with Unix epoch",
			args: args{
				username: "",
				issuedAt: time.Unix(0, 0),
			},
			want: "-0",
		},
		{
			name: "username with Unix epoch",
			args: args{
				username: "username",
				issuedAt: time.Unix(0, 0),
			},
			want: "username-0",
		},
		{
			name: "username with specific timestamp",
			args: args{
				username: "testuser",
				issuedAt: time.Unix(1234567890, 0),
			},
			want: "testuser-1234567890",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateJTI(tt.args.username, tt.args.issuedAt); got != tt.want {
				t.Errorf("generateJTI() = %v, want %v", got, tt.want)
			}
		})
	}
}
