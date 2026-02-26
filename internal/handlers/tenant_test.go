package handlers

import (
	ldapPkg "ldap-jwt-generator/internal/ldap"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

	if !strings.Contains(w.Body.String(), "Tenant-Id header is required") {
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

	if !strings.Contains(w.Body.String(), "Unknown tenant") {
		t.Errorf("Expected error message about unknown tenant, got: %s", w.Body.String())
	}
}
