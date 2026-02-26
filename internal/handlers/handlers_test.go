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

	"k8s.io/utils/strings/slices"
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

// TestMiddlewareChain_MultipleUserRoles tests full chain with different user types
func TestMiddlewareChain_MultipleUserRoles(t *testing.T) {
	testCases := []struct {
		name           string
		username       string
		password       string
		expectedGroups []string
	}{
		{
			name:           "Admin user",
			username:       "admin",
			password:       "adminpass",
			expectedGroups: []string{"ADMIN_KUBERNETES", "ALL_USERS"},
		},
		{
			name:           "Viewer user",
			username:       "viewer",
			password:       "viewerpass",
			expectedGroups: []string{"CLUSTER_VIEWER"},
		},
		{
			name:           "Service account",
			username:       "svc-account",
			password:       "svcpass",
			expectedGroups: []string{"SERVICE_ACCOUNTS", "AUTOMATION"},
		},
		{
			name:           "Regular user",
			username:       "regularuser",
			password:       "regularpass",
			expectedGroups: []string{"PROJECT_A", "PROJECT_B", "DEVELOPERS"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuth := &mockTenantAuthenticator{
				authNFunc: func(username, password string) (*user.Details, error) {
					if username == tc.username && password == tc.password {
						return &user.Details{
							Name:  username,
							Email: username + "@example.com",
							DN:    "CN=" + username + ",DC=example,DC=org",
						}, nil
					}
					return nil, fmt.Errorf("invalid credentials")
				},
				authZFunc: func(userDetails *user.Details) (*user.Details, error) {
					userDetails.Groups = tc.expectedGroups
					return userDetails, nil
				},
			}

			finalHandlerCalled := false
			finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				finalHandlerCalled = true

				userValue := r.Context().Value(UserContextKey)
				if userValue == nil {
					t.Fatal("Expected user in context")
				}

				userDetails := userValue.(*user.Details)
				if userDetails.Name != tc.username {
					t.Errorf("Expected username '%s', got '%s'", tc.username, userDetails.Name)
				}

				if len(userDetails.Groups) != len(tc.expectedGroups) {
					t.Errorf("Expected %d groups, got %d", len(tc.expectedGroups), len(userDetails.Groups))
				}

				for _, expectedGroup := range tc.expectedGroups {
					if !slices.Contains(userDetails.Groups, expectedGroup) {
						t.Errorf("Expected groups to contain '%s'", expectedGroup)
					}
				}

				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/token", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(tc.username + ":" + tc.password))
			req.Header.Set("Authorization", "Basic "+auth)

			ctx := context.WithValue(req.Context(), TenantAuthenticatorKey, mockAuth)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()

			handler := WithBasicAuth(WithGroupEnrichment(finalHandler))
			handler.ServeHTTP(w, req)

			if !finalHandlerCalled {
				t.Error("Final handler was not called")
			}

			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		})
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
