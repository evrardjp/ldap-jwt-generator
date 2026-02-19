package e2e

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"ldap-jwt-generator/internal/handlers"
	jwtPkg "ldap-jwt-generator/internal/jwt"
	ldapPkg "ldap-jwt-generator/internal/ldap"
	"ldap-jwt-generator/internal/user"
)

// Mock LDAP authenticator for e2e testing
type mockE2EAuth struct {
	tenantID  string
	users     map[string]mockUser  // username -> user details + password
	userGroups map[string][]string // username -> groups
}

type mockUser struct {
	password string
	details  *user.Details
}

func (m *mockE2EAuth) AuthN(username, password string) (*user.Details, error) {
	u, exists := m.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	if u.password != password {
		return nil, fmt.Errorf("invalid password")
	}
	return u.details, nil
}

func (m *mockE2EAuth) AuthZ(userDetails *user.Details) (*user.Details, error) {
	groups, exists := m.userGroups[userDetails.Username]
	if !exists {
		groups = []string{} // User with no groups
	}
	userDetails.Groups = groups
	return userDetails, nil
}

// Mock tenant registry for e2e testing
type mockE2ERegistry struct {
	authenticators map[string]*ldapPkg.TenantAuthenticator
	mockAuths      map[string]*mockE2EAuth
}

func (m *mockE2ERegistry) GetAuthenticator(tenantID string) (*ldapPkg.TenantAuthenticator, error) {
	_, exists := m.mockAuths[tenantID]
	if !exists {
		return nil, fmt.Errorf("unknown tenant: %s", tenantID)
	}
	// We can't create a real TenantAuthenticator without LDAP, so we return a placeholder
	// The actual mock will be used via context in the middleware
	return &ldapPkg.TenantAuthenticator{}, nil
}

// Helper to create test server
func createTestServer(t *testing.T) (*httptest.Server, *jwtPkg.TokenIssuer, *mockE2ERegistry) {
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

	tokenIssuer := &jwtPkg.TokenIssuer{
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		TokenDuration: duration,
		IssuerFQDN:    "ldap-jwt-generator.test.local",
	}

	// Create mock tenant registry with test users
	registry := &mockE2ERegistry{
		mockAuths: make(map[string]*mockE2EAuth),
	}

	// Tenant 1: admin user
	registry.mockAuths["tenant1"] = &mockE2EAuth{
		tenantID: "tenant1",
		users: map[string]mockUser{
			"admin-user": {
				password: "admin-pass",
				details: &user.Details{
					Username: "admin-user",
					Email:    "admin@tenant1.local",
					UserDN:   "CN=Admin User,OU=Users,DC=tenant1,DC=local",
				},
			},
		},
		userGroups: map[string][]string{
			"admin-user": {"ADMIN_KUBERNETES", "ALL_USERS"},
		},
	}

	// Tenant 2: customerops and regular users
	registry.mockAuths["tenant2"] = &mockE2EAuth{
		tenantID: "tenant2",
		users: map[string]mockUser{
			"customerops-user": {
				password: "customerops-pass",
				details: &user.Details{
					Username: "customerops-user",
					Email:    "customerops@tenant2.local",
					UserDN:   "CN=CustomerOps User,OU=Users,DC=tenant2,DC=local",
				},
			},
			"appops-user": {
				password: "appops-pass",
				details: &user.Details{
					Username: "appops-user",
					Email:    "appops@tenant2.local",
					UserDN:   "CN=AppOps User,OU=Users,DC=tenant2,DC=local",
				},
			},
			"viewer-user": {
				password: "viewer-pass",
				details: &user.Details{
					Username: "viewer-user",
					Email:    "viewer@tenant2.local",
					UserDN:   "CN=Viewer User,OU=Users,DC=tenant2,DC=local",
				},
			},
			"service-user": {
				password: "service-pass",
				details: &user.Details{
					Username: "service-user",
					Email:    "service@tenant2.local",
					UserDN:   "CN=Service User,OU=ServiceAccounts,DC=tenant2,DC=local",
				},
			},
			"regular-user": {
				password: "regular-pass",
				details: &user.Details{
					Username: "regular-user",
					Email:    "regular@tenant2.local",
					UserDN:   "CN=Regular User,OU=Users,DC=tenant2,DC=local",
				},
			},
			"no-groups-user": {
				password: "no-groups-pass",
				details: &user.Details{
					Username: "no-groups-user",
					Email:    "nogroups@tenant2.local",
					UserDN:   "CN=No Groups User,OU=Users,DC=tenant2,DC=local",
				},
			},
		},
		userGroups: map[string][]string{
			"customerops-user": {"CUSTOMER_OPS", "PROJECT_ALPHA"},
			"appops-user":      {"APPLICATION_OPS", "DEVELOPERS"},
			"viewer-user":      {"CLUSTER_VIEWER"},
			"service-user":     {"SERVICE_ACCOUNTS", "AUTOMATED_PROCESSES"},
			"regular-user":     {"PROJECT_BETA", "PROJECT_GAMMA"},
			"no-groups-user":   {},
		},
	}

	// Create HTTP mux with modified middleware that uses mock auth
	mux := http.NewServeMux()

	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		// Custom middleware chain using mock authenticators
		tenantID := r.Header.Get("Tenant-Id")
		if tenantID == "" {
			http.Error(w, "Bad Request: Tenant-Id header is required", http.StatusBadRequest)
			return
		}

		mockAuth, exists := registry.mockAuths[tenantID]
		if !exists {
			http.Error(w, "Bad Request: Unknown tenant", http.StatusBadRequest)
			return
		}

		// Extract Basic Auth
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Authenticate
		userDetails, err := mockAuth.AuthN(username, password)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Authorize (fetch groups)
		userDetails, err = mockAuth.AuthZ(userDetails)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Set context for token generation
		ctx := r.Context()
		ctx = handlers.WithUserInContext(ctx, userDetails)
		ctx = handlers.WithTenantIDInContext(ctx, tenantID)
		r = r.WithContext(ctx)

		// Generate JWT
		tokenIssuer.GenerateJWT(w, r)
	})

	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Metrics endpoint\n"))
	})

	server := httptest.NewServer(mux)

	return server, tokenIssuer, registry
}

// Test: Admin user from tenant1
func TestE2E_AdminUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant1")
	auth := base64.StdEncoding.EncodeToString([]byte("admin-user:admin-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	// Read and verify token
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	tokenString := string(tokenBytes)

	token, err := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if claims.Username != "admin-user" {
		t.Errorf("Expected username 'admin-user', got '%s'", claims.Username)
	}
	if claims.TenantID != "tenant1" {
		t.Errorf("Expected tenantID 'tenant1', got '%s'", claims.TenantID)
	}
	if !contains(claims.Groups, "ADMIN_KUBERNETES") {
		t.Error("Expected groups to contain 'ADMIN_KUBERNETES'")
	}
	if claims.Issuer != "ldap-jwt-generator.test.local" {
		t.Errorf("Expected issuer 'ldap-jwt-generator.test.local', got '%s'", claims.Issuer)
	}
}

// Test: CustomerOps user from tenant2
func TestE2E_CustomerOpsUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("customerops-user:customerops-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if claims.Username != "customerops-user" {
		t.Errorf("Expected username 'customerops-user', got '%s'", claims.Username)
	}
	if !contains(claims.Groups, "CUSTOMER_OPS") {
		t.Error("Expected groups to contain 'CUSTOMER_OPS'")
	}
	if !contains(claims.Groups, "PROJECT_ALPHA") {
		t.Error("Expected groups to contain 'PROJECT_ALPHA'")
	}
}

// Test: AppOps user from tenant2
func TestE2E_AppOpsUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("appops-user:appops-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if !contains(claims.Groups, "APPLICATION_OPS") {
		t.Error("Expected groups to contain 'APPLICATION_OPS'")
	}
	if !contains(claims.Groups, "DEVELOPERS") {
		t.Error("Expected groups to contain 'DEVELOPERS'")
	}
}

// Test: Viewer user from tenant2
func TestE2E_ViewerUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("viewer-user:viewer-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if !contains(claims.Groups, "CLUSTER_VIEWER") {
		t.Error("Expected groups to contain 'CLUSTER_VIEWER'")
	}
}

// Test: Service account user
func TestE2E_ServiceAccountUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("service-user:service-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if !contains(claims.Groups, "SERVICE_ACCOUNTS") {
		t.Error("Expected groups to contain 'SERVICE_ACCOUNTS'")
	}
}

// Test: Regular user with multiple projects
func TestE2E_RegularUser(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("regular-user:regular-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if len(claims.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(claims.Groups))
	}
	if !contains(claims.Groups, "PROJECT_BETA") || !contains(claims.Groups, "PROJECT_GAMMA") {
		t.Error("Expected groups to contain PROJECT_BETA and PROJECT_GAMMA")
	}
}

// Test: User with no groups
func TestE2E_UserWithNoGroups(t *testing.T) {
	server, tokenIssuer, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant2")
	auth := base64.StdEncoding.EncodeToString([]byte("no-groups-user:no-groups-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenString := string(tokenBytes)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return tokenIssuer.PublicKey, nil
	})

	claims := token.Claims.(*jwtPkg.AuthJWTClaims)

	if len(claims.Groups) != 0 {
		t.Errorf("Expected 0 groups, got %d", len(claims.Groups))
	}
}

// Test: Missing Tenant-Id header
func TestE2E_MissingTenantHeader(t *testing.T) {
	server, _, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	// No Tenant-Id header
	auth := base64.StdEncoding.EncodeToString([]byte("admin-user:admin-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

// Test: Invalid tenant ID
func TestE2E_InvalidTenant(t *testing.T) {
	server, _, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "non-existent-tenant")
	auth := base64.StdEncoding.EncodeToString([]byte("admin-user:admin-pass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

// Test: Missing Authorization header
func TestE2E_MissingAuthHeader(t *testing.T) {
	server, _, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant1")
	// No Authorization header

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("Expected WWW-Authenticate header to be set")
	}
}

// Test: Invalid credentials
func TestE2E_InvalidCredentials(t *testing.T) {
	server, _, _ := createTestServer(t)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/token", nil)
	req.Header.Set("Tenant-Id", "tenant1")
	auth := base64.StdEncoding.EncodeToString([]byte("admin-user:wrong-password"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

// Test: Metrics endpoint
func TestE2E_MetricsEndpoint(t *testing.T) {
	server, _, _ := createTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
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
