package e2e

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	jwtPkg "ldap-jwt-generator/internal/jwt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	apiBaseURL = "http://localhost:8080"
	tenantID   = "tenant1"
)

// TestE2E_RealLDAP_ValidUser tests successful authentication with real LDAP
func TestE2E_RealLDAP_ValidUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	testCases := []struct {
		name           string
		username       string
		password       string
		expectedGroups []string
	}{
		{
			name:           "admin-kube1 with ADMIN_KUBERNETES group",
			username:       "admin-kube1",
			password:       "somepass",
			expectedGroups: []string{"ADMIN_KUBERNETES"},
		},
		{
			name:           "developer1 with DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN group",
			username:       "developer1",
			password:       "somepass",
			expectedGroups: []string{"DL_KUB_CAGIPHP_PROJET-TOTO-DEV_ADMIN"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
			req.Header.Set("Tenant-Id", tenantID)
			auth := base64.StdEncoding.EncodeToString([]byte(tc.username + ":" + tc.password))
			req.Header.Set("Authorization", "Basic "+auth)

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Expected status %d, got %d. Body: %s", http.StatusCreated, resp.StatusCode, string(body))
			}

			// Read and verify token
			tokenBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			tokenString := string(tokenBytes)

			// Parse token (we need to load the public key)
			publicKeyPEM, err := os.ReadFile("../../test/ecdsa-pub.pem")
			if err != nil {
				t.Fatalf("Failed to read public key: %v", err)
			}

			publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyPEM)
			if err != nil {
				t.Fatalf("Failed to parse public key: %v", err)
			}

			token, err := jwt.ParseWithClaims(tokenString, &jwtPkg.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			if err != nil {
				t.Fatalf("Failed to parse token: %v", err)
			}

			claims := token.Claims.(*jwtPkg.AuthJWTClaims)

			// Verify username
			if claims.User != tc.username {
				t.Errorf("Expected username '%s', got '%s'", tc.username, claims.User)
			}

			// Verify tenant ID
			if claims.Tenant != tenantID {
				t.Errorf("Expected tenantID '%s', got '%s'", tenantID, claims.Tenant)
			}

			// Verify groups
			for _, expectedGroup := range tc.expectedGroups {
				if !containsString(claims.Groups, expectedGroup) {
					t.Errorf("Expected groups to contain '%s', got %v", expectedGroup, claims.Groups)
				}
			}

			// Verify issuer
			if claims.Issuer != "ldap-jwt-generator.test.local" {
				t.Errorf("Expected issuer 'ldap-jwt-generator.test.local', got '%s'", claims.Issuer)
			}

			// Verify email exists
			if claims.Contact == "" {
				t.Error("Expected email to be set")
			}
		})
	}
}

// TestE2E_RealLDAP_WrongPassword tests authentication failure with wrong password
func TestE2E_RealLDAP_WrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	req.Header.Set("Tenant-Id", tenantID)
	auth := base64.StdEncoding.EncodeToString([]byte("admin-kube1:wrongpassword"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

// TestE2E_RealLDAP_NonExistentUser tests authentication failure with non-existent user
func TestE2E_RealLDAP_NonExistentUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	req.Header.Set("Tenant-Id", tenantID)
	auth := base64.StdEncoding.EncodeToString([]byte("nonexistent:somepass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

// TestE2E_RealLDAP_UserWithNoGroups tests that users with no groups are rejected
func TestE2E_RealLDAP_UserWithNoGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	req.Header.Set("Tenant-Id", tenantID)
	auth := base64.StdEncoding.EncodeToString([]byte("no-group-user:somepass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status %d (Forbidden) for user with no groups, got %d. Body: %s",
			http.StatusForbidden, resp.StatusCode, string(body))
	}

	// Verify error message mentions groups
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !contains(bodyStr, "group") {
		t.Errorf("Expected error message to mention 'group', got: %s", bodyStr)
	}
}

// TestE2E_RealLDAP_MissingTenantHeader tests missing Tenant-Id header
func TestE2E_RealLDAP_MissingTenantHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	// No Tenant-Id header
	auth := base64.StdEncoding.EncodeToString([]byte("admin-kube1:somepass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

// TestE2E_RealLDAP_InvalidTenant tests invalid tenant ID
func TestE2E_RealLDAP_InvalidTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	req.Header.Set("Tenant-Id", "invalid-tenant")
	auth := base64.StdEncoding.EncodeToString([]byte("admin-kube1:somepass"))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

// TestE2E_RealLDAP_MissingAuthHeader tests missing Authorization header
func TestE2E_RealLDAP_MissingAuthHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	req, _ := http.NewRequest("GET", apiBaseURL+"/token", nil)
	req.Header.Set("Tenant-Id", tenantID)
	// No Authorization header

	client := &http.Client{Timeout: 10 * time.Second}
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

// TestE2E_RealLDAP_MetricsEndpoint tests the metrics endpoint
func TestE2E_RealLDAP_MetricsEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiBaseURL + "/metrics")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

// Helper functions
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && containsSubstring(s, substr)
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
