package ldap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Test validateTenantID function

func TestValidateTenantID_Valid(t *testing.T) {
	validIDs := []string{
		"tenant1",
		"tenant-2",
		"tenant_3",
		"production",
		"dev-environment",
		"customer_a",
	}

	for _, tenantID := range validIDs {
		err := validateTenantID(tenantID)
		if err != nil {
			t.Errorf("Expected tenant ID '%s' to be valid, got error: %v", tenantID, err)
		}
	}
}

func TestValidateTenantID_Empty(t *testing.T) {
	err := validateTenantID("")
	if err == nil {
		t.Error("Expected error for empty tenant ID, got nil")
	}
	if err.Error() != "tenant ID cannot be empty" {
		t.Errorf("Expected error 'tenant ID cannot be empty', got '%v'", err)
	}
}

func TestValidateTenantID_PathTraversal(t *testing.T) {
	invalidIDs := []string{
		"../etc/passwd",
		"../../secret",
		"tenant/../admin",
		"normal..tenant",
	}

	for _, tenantID := range invalidIDs {
		err := validateTenantID(tenantID)
		if err == nil {
			t.Errorf("Expected tenant ID '%s' to be invalid (contains ..), got no error", tenantID)
		}
		if err.Error() != "tenant ID contains invalid characters" {
			t.Errorf("Expected error 'tenant ID contains invalid characters', got '%v'", err)
		}
	}
}

func TestValidateTenantID_ForwardSlash(t *testing.T) {
	invalidIDs := []string{
		"tenant/subdir",
		"/etc/tenant",
		"tenant/",
		"/",
	}

	for _, tenantID := range invalidIDs {
		err := validateTenantID(tenantID)
		if err == nil {
			t.Errorf("Expected tenant ID '%s' to be invalid (contains /), got no error", tenantID)
		}
	}
}

func TestValidateTenantID_Backslash(t *testing.T) {
	invalidIDs := []string{
		"tenant\\subdir",
		"\\windows\\path",
		"tenant\\",
	}

	for _, tenantID := range invalidIDs {
		err := validateTenantID(tenantID)
		if err == nil {
			t.Errorf("Expected tenant ID '%s' to be invalid (contains \\), got no error", tenantID)
		}
	}
}

// Test GetAuthenticator method

func TestGetAuthenticator_ValidTenant(t *testing.T) {
	// Create a test registry with mock authenticators
	baseConfig := &BaseConfig{
		Host:         "ldap.test.com",
		Port:         389,
		BindDN:       "cn=admin,dc=test,dc=com",
		BindPassword: "password",
	}
	ldapClient := NewLDAPClient(baseConfig)

	tenantConfig := &TenantConfig{
		UserBase:   "ou=users,dc=test,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
		},
	}

	authenticator := &TenantAuthenticator{
		ldapClient:   ldapClient,
		tenantConfig: tenantConfig,
	}

	registry := &TenantRegistry{
		authenticators: map[string]*TenantAuthenticator{
			"tenant1": authenticator,
		},
	}

	// Test successful lookup
	auth, err := registry.GetAuthenticator("tenant1")
	if err != nil {
		t.Fatalf("Expected no error for valid tenant, got %v", err)
	}
	if auth != authenticator {
		t.Error("Expected to get the same authenticator we put in")
	}
}

func TestGetAuthenticator_UnknownTenant(t *testing.T) {
	registry := &TenantRegistry{
		authenticators: map[string]*TenantAuthenticator{
			"tenant1": nil, // Just need the key
		},
	}

	_, err := registry.GetAuthenticator("unknown-tenant")
	if err == nil {
		t.Error("Expected error for unknown tenant, got nil")
	}
	if err.Error() != "unknown tenant: unknown-tenant" {
		t.Errorf("Expected error 'unknown tenant: unknown-tenant', got '%v'", err)
	}
}

func TestGetAuthenticator_InvalidTenantID(t *testing.T) {
	registry := &TenantRegistry{
		authenticators: map[string]*TenantAuthenticator{},
	}

	invalidIDs := []string{
		"../etc/passwd",
		"tenant/subdir",
		"tenant\\windows",
		"",
	}

	for _, tenantID := range invalidIDs {
		_, err := registry.GetAuthenticator(tenantID)
		if err == nil {
			t.Errorf("Expected error for invalid tenant ID '%s', got nil", tenantID)
		}
	}
}

// Test loadTenantConfigFile with temp files

func TestLoadTenantConfigFile_Valid(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenant1.json")

	validConfig := TenantConfig{
		UserBase:   "ou=users,dc=test,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=test,dc=com",
				Filter: "(member=%s)",
			},
		},
	}

	data, _ := json.Marshal(validConfig)
	err := os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test loading
	config, err := loadTenantConfigFile(configPath)
	if err != nil {
		t.Fatalf("Expected no error loading valid config, got %v", err)
	}

	if config.UserBase != validConfig.UserBase {
		t.Errorf("Expected UserBase '%s', got '%s'", validConfig.UserBase, config.UserBase)
	}
	if config.UserFilter != validConfig.UserFilter {
		t.Errorf("Expected UserFilter '%s', got '%s'", validConfig.UserFilter, config.UserFilter)
	}
	if len(config.GroupSources) != 1 {
		t.Errorf("Expected 1 GroupSource, got %d", len(config.GroupSources))
	}
}

func TestLoadTenantConfigFile_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.json")

	// Write invalid JSON
	err := os.WriteFile(configPath, []byte("{invalid json}"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = loadTenantConfigFile(configPath)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestLoadTenantConfigFile_MissingFile(t *testing.T) {
	_, err := loadTenantConfigFile("/nonexistent/path/config.json")
	if err == nil {
		t.Error("Expected error for missing file, got nil")
	}
}

func TestLoadTenantConfigFile_ValidationFailure(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid-config.json")

	// Create config missing required fields
	invalidConfig := TenantConfig{
		UserBase: "ou=users,dc=test,dc=com",
		// Missing UserFilter and GroupSources
	}

	data, _ := json.Marshal(invalidConfig)
	err := os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err = loadTenantConfigFile(configPath)
	if err == nil {
		t.Error("Expected validation error, got nil")
	}
}

func TestLoadTenantConfigFile_DefaultUserFilter(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Create config WITHOUT UserFilter to test default
	configWithoutFilter := map[string]interface{}{
		"userBase": "ou=users,dc=test,dc=com",
		// UserFilter omitted
		"groupSources": []map[string]string{
			{
				"base":   "ou=groups,dc=test,dc=com",
				"filter": "(member=%s)",
			},
		},
	}

	data, _ := json.Marshal(configWithoutFilter)
	err := os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	config, err := loadTenantConfigFile(configPath)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check that default UserFilter was applied
	if config.UserFilter != "(cn=%s)" {
		t.Errorf("Expected default UserFilter '(cn=%%s)', got '%s'", config.UserFilter)
	}
}

func TestLoadTenantConfigFile_MultipleGroupSources(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "multi-groups.json")

	configWithMultipleGroups := TenantConfig{
		UserBase:   "ou=users,dc=test,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=test,dc=com",
				Filter: "(member=%s)",
			},
			{
				Base:   "ou=roles,dc=test,dc=com",
				Filter: "(uniqueMember=%s)",
			},
			{
				Base:   "ou=teams,dc=test,dc=com",
				Filter: "(memberUid=%s)",
			},
		},
	}

	data, _ := json.Marshal(configWithMultipleGroups)
	err := os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	config, err := loadTenantConfigFile(configPath)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(config.GroupSources) != 3 {
		t.Errorf("Expected 3 GroupSources, got %d", len(config.GroupSources))
	}
}
