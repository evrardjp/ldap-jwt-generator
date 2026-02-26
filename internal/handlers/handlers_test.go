package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ldapPkg "ldap-jwt-generator/internal/ldap"
	"ldap-jwt-generator/internal/user"
)

// Mock TenantRegistry for testing (implements ldapPkg.TenantRegistryInterface)
type mockTenantRegistry struct {
	authenticators map[string]*ldapPkg.TenantAuthenticator
}

func (m *mockTenantRegistry) GetAuthenticator(tenantID string) (*ldapPkg.TenantAuthenticator, error) {
	// For testing, we just check if tenantID exists
	// We don't actually return a valid authenticator since that would require LDAP connection
	_, exists := m.authenticators[tenantID]
	if !exists {
		return nil, fmt.Errorf("unknown tenant: %s", tenantID)
	}
	// Return a placeholder - actual authenticator will be mocked separately
	return &ldapPkg.TenantAuthenticator{}, nil
}

// TestWithTenantConfig_ValidTenant tests that valid tenant ID is accepted
func TestWithTenantConfig_ValidTenant(t *testing.T) {
	// Create mock registry with tenant1
	registry := &mockTenantRegistry{
		authenticators: map[string]*ldapPkg.TenantAuthenticator{
			"tenant1": nil, // Authenticator doesn't matter for this test
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true

		// Verify tenant ID is in context
		tenantID := r.Context().Value(TenantIDKey)
		if tenantID != "tenant1" {
			t.Errorf("Expected tenantID 'tenant1' in context, got %v", tenantID)
		}

		// Verify authenticator is in context
		auth := r.Context().Value(TenantAuthenticatorKey)
		if auth == nil {
			t.Error("Expected authenticator in context, got nil")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := WithTenantConfig(registry, next)

	req := httptest.NewRequest("GET", "/token", nil)
	req.Header.Set("Tenant-Id", "tenant1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Next handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestWithTenantConfig_MissingTenantHeader tests that missing Tenant-Id returns 400
func TestWithTenantConfig_MissingTenantHeader(t *testing.T) {
	registry := &mockTenantRegistry{
		authenticators: make(map[string]*ldapPkg.TenantAuthenticator),
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := WithTenantConfig(registry, next)

	req := httptest.NewRequest("GET", "/token", nil)
	// No Tenant-Id header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called")
	}

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !contains(w.Body.String(), "Tenant-Id header is required") {
		t.Errorf("Expected error message about Tenant-Id, got: %s", w.Body.String())
	}
}

// TestWithTenantConfig_InvalidTenant tests that invalid tenant ID returns 400
func TestWithTenantConfig_InvalidTenant(t *testing.T) {
	registry := &mockTenantRegistry{
		authenticators: map[string]*ldapPkg.TenantAuthenticator{
			"tenant1": nil,
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := WithTenantConfig(registry, next)

	req := httptest.NewRequest("GET", "/token", nil)
	req.Header.Set("Tenant-Id", "invalid-tenant")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called")
	}

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !contains(w.Body.String(), "Unknown tenant") {
		t.Errorf("Expected error message about unknown tenant, got: %s", w.Body.String())
	}
}

// TestWithBasicAuth_ValidCredentials tests successful authentication
func TestWithBasicAuth_ValidCredentials(t *testing.T) {
	// Create a mock authenticator that accepts specific credentials
	mockAuth := &mockTenantAuthenticator{
		authNFunc: func(username, password string) (*user.Details, error) {
			if username == "testuser" && password == "testpass" {
				return &user.Details{
					Name:  "testuser",
					Email: "testuser@example.com",
					DN:    "CN=Test Name,DC=example,DC=org",
				}, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true

		// Verify user is in context
		userValue := r.Context().Value(UserContextKey)
		if userValue == nil {
			t.Error("Expected user in context, got nil")
		}

		userDetails := userValue.(*user.Details)
		if userDetails.Name != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", userDetails.Name)
		}

		w.WriteHeader(http.StatusOK)
	})

	// Set up context with authenticator
	ctx := context.WithValue(context.Background(), TenantAuthenticatorKey, mockAuth)
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)

	// Add Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	handler := WithBasicAuth(next)
	handler.ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Next handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestWithBasicAuth_MissingAuthHeader tests missing Authorization header
func TestWithBasicAuth_MissingAuthHeader(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	// Set up context with authenticator
	ctx := context.WithValue(context.Background(), TenantAuthenticatorKey, mockAuth)
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler := WithBasicAuth(next)
	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	// Verify WWW-Authenticate header is set
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("Expected WWW-Authenticate header to be set")
	}
}

// TestWithBasicAuth_InvalidCredentials tests authentication failure
func TestWithBasicAuth_InvalidCredentials(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authNFunc: func(username, password string) (*user.Details, error) {
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	ctx := context.WithValue(context.Background(), TenantAuthenticatorKey, mockAuth)
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)

	auth := base64.StdEncoding.EncodeToString([]byte("wronguser:wrongpass"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	handler := WithBasicAuth(next)
	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// TestWithAuthorization_FetchesGroups tests that groups are fetched and added to user
func TestWithAuthorization_FetchesGroups(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authZFunc: func(userDetails *user.Details) (*user.Details, error) {
			if userDetails.DN == "CN=Test Name,DC=example,DC=org" {
				userDetails.Groups = []string{"ADMIN_GROUP", "DEVELOPER_GROUP"}
				return userDetails, nil
			}
			return nil, fmt.Errorf("user not found")
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true

		// Verify user has groups
		userValue := r.Context().Value(UserContextKey)
		userDetails := userValue.(*user.Details)

		if len(userDetails.Groups) != 2 {
			t.Errorf("Expected 2 groups, got %d", len(userDetails.Groups))
		}

		if !containsString(userDetails.Groups, "ADMIN_GROUP") {
			t.Error("Expected groups to contain 'ADMIN_GROUP'")
		}

		if !containsString(userDetails.Groups, "DEVELOPER_GROUP") {
			t.Error("Expected groups to contain 'DEVELOPER_GROUP'")
		}

		w.WriteHeader(http.StatusOK)
	})

	userDetails := &user.Details{
		Name:  "testuser",
		Email: "testuser@example.com",
		DN:    "CN=Test Name,DC=example,DC=org",
	}

	ctx := context.WithValue(context.Background(), UserContextKey, userDetails)
	ctx = context.WithValue(ctx, TenantAuthenticatorKey, mockAuth)

	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler := WithGroupEnrichment(next)
	handler.ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Next handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestWithAuthorization_GroupFetchError tests error handling when group fetch fails
func TestWithAuthorization_GroupFetchError(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authZFunc: func(userDetails *user.Details) (*user.Details, error) {
			return nil, fmt.Errorf("LDAP connection error")
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	userDetails := &user.Details{
		Name:  "testuser",
		Email: "testuser@example.com",
		DN:    "CN=Test Name,DC=example,DC=org",
	}

	ctx := context.WithValue(context.Background(), UserContextKey, userDetails)
	ctx = context.WithValue(ctx, TenantAuthenticatorKey, mockAuth)

	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler := WithGroupEnrichment(next)
	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called on error")
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// TestMiddlewareChain tests the full middleware chain
func TestMiddlewareChain(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authNFunc: func(username, password string) (*user.Details, error) {
			return &user.Details{
				Name:  "chainuser",
				Email: "chainuser@example.com",
				DN:    "CN=Chain Name,DC=example,DC=org",
			}, nil
		},
		authZFunc: func(userDetails *user.Details) (*user.Details, error) {
			userDetails.Groups = []string{"CHAIN_GROUP"}
			return userDetails, nil
		},
	}

	finalHandlerCalled := false
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHandlerCalled = true

		// Verify all context values are present
		tenantID := r.Context().Value(TenantIDKey)
		if tenantID != "tenant-chain" {
			t.Errorf("Expected tenantID 'tenant-chain', got %v", tenantID)
		}

		userValue := r.Context().Value(UserContextKey)
		if userValue == nil {
			t.Fatal("Expected user in context")
		}

		userDetails := userValue.(*user.Details)
		if userDetails.Name != "chainuser" {
			t.Errorf("Expected username 'chainuser', got '%s'", userDetails.Name)
		}

		if len(userDetails.Groups) != 1 || userDetails.Groups[0] != "CHAIN_GROUP" {
			t.Errorf("Expected groups ['CHAIN_GROUP'], got %v", userDetails.Groups)
		}

		w.WriteHeader(http.StatusOK)
	})

	// Build middleware chain (but we can't fully test it without real TenantAuthenticator)
	// This test demonstrates the pattern
	req := httptest.NewRequest("GET", "/token", nil)
	req.Header.Set("Tenant-Id", "tenant-chain")
	auth := base64.StdEncoding.EncodeToString([]byte("chainuser:chainpass"))
	req.Header.Set("Authorization", "Basic "+auth)

	// Manually set up context for this test (in real app, WithTenantConfig does this)
	ctx := context.WithValue(req.Context(), TenantAuthenticatorKey, mockAuth)
	ctx = context.WithValue(ctx, TenantIDKey, "tenant-chain")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Chain: BasicAuth -> Authorization -> FinalHandler
	handler := WithBasicAuth(WithGroupEnrichment(finalHandler))
	handler.ServeHTTP(w, req)

	if !finalHandlerCalled {
		t.Error("Final handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Mock TenantAuthenticator for testing (implements Authenticator and Authorizer interfaces)
type mockTenantAuthenticator struct {
	authNFunc func(username, password string) (*user.Details, error)
	authZFunc func(userDetails *user.Details) (*user.Details, error)
}

func (m *mockTenantAuthenticator) AuthN(username, password string) (*user.Details, error) {
	if m.authNFunc != nil {
		return m.authNFunc(username, password)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockTenantAuthenticator) AuthZ(userDetails *user.Details) (*user.Details, error) {
	if m.authZFunc != nil {
		return m.authZFunc(userDetails)
	}
	return nil, fmt.Errorf("not implemented")
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
