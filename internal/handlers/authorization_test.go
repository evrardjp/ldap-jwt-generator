package handlers

import (
	"context"
	"fmt"
	"ldap-jwt-generator/internal/user"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestWithGroupEnrichment_UserWithNoGroups tests CRITICAL business rule: users with no groups are denied
func TestWithGroupEnrichment_UserWithNoGroups(t *testing.T) {
	mockAuth := &mockTenantAuthenticator{
		authZFunc: func(userDetails *user.Details) (*user.Details, error) {
			// Return user with ZERO groups (empty slice)
			userDetails.Groups = []string{}
			return userDetails, nil
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	userDetails := &user.Details{
		Name:  "no-group-user",
		Email: "nogroups@example.com",
		DN:    "CN=No Groups,DC=example,DC=org",
	}

	ctx := context.WithValue(context.Background(), UserContextKey, userDetails)
	ctx = context.WithValue(ctx, TenantAuthenticatorKey, mockAuth)

	req := httptest.NewRequest("GET", "/token", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler := WithGroupEnrichment(next)
	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should NOT be called when user has no groups")
	}

	// CRITICAL: Users with no groups must be denied with HTTP 403
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d (Forbidden) for user with no groups, got %d", http.StatusForbidden, w.Code)
	}

	// Verify error message mentions groups
	if !strings.Contains(w.Body.String(), "group") {
		t.Errorf("Expected error message to mention 'group', got: %s", w.Body.String())
	}
}

// TestWithGroupEnrichment_FetchesGroups tests that groups are fetched and added to user
func TestWithGroupEnrichment_FetchesGroups(t *testing.T) {
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

		if !slices.Contains(userDetails.Groups, "ADMIN_GROUP") {
			t.Error("Expected groups to contain 'ADMIN_GROUP'")
		}

		if !slices.Contains(userDetails.Groups, "DEVELOPER_GROUP") {
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

// TestWithGroupEnrichment_GroupFetchError tests error handling when group fetch fails
func TestWithGroupEnrichment_GroupFetchError(t *testing.T) {
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
