package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"ldap-jwt-generator/internal/user"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

// TestWithBasicAuth_EmptyPassword tests edge case of user with empty password
func TestWithBasicAuth_EmptyPassword(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authNFunc: func(username, password string) (*user.Details, error) {
			// Empty password should fail authentication
			if password == "" {
				return nil, fmt.Errorf("empty password not allowed")
			}
			return &user.Details{Name: username}, nil
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	ctx := context.WithValue(context.Background(), TenantAuthenticatorKey, mockAuth)
	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)

	// Create Basic Auth with empty password: "username:"
	auth := base64.StdEncoding.EncodeToString([]byte("testuser:"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	handler := WithBasicAuth(next)
	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should not be called with empty password")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}
