package ldap

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const DefaultTenantConfigDir = "/etc/ldap-jwt-generator/ldap-configs"

// TenantRegistryInterface defines the interface for tenant registry (for testing)
type TenantRegistryInterface interface {
	GetAuthenticator(tenantID string) (*TenantAuthenticator, error)
}

// TenantRegistry holds all tenant authenticators, loaded at startup
type TenantRegistry struct {
	authenticators map[string]*TenantAuthenticator
}

// NewTenantRegistry loads all tenant configs from directory at startup
func NewTenantRegistry(baseConfig *BaseConfig) (*TenantRegistry, error) {
	registry := &TenantRegistry{
		authenticators: make(map[string]*TenantAuthenticator),
	}

	// Read all JSON files from config directory
	entries, err := os.ReadDir(DefaultTenantConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read tenant config directory: %w", err)
	}

	// Create shared LDAP client for all tenants
	ldapClient := NewLDAPClient(baseConfig)

	// Load each tenant config
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Extract tenant ID from filename (remove .json extension)
		tenantID := strings.TrimSuffix(entry.Name(), ".json")

		// Validate tenant ID format
		if err := validateTenantID(tenantID); err != nil {
			return nil, fmt.Errorf("invalid tenant config filename %s: %w", entry.Name(), err)
		}

		// Load and validate config
		configPath := filepath.Join(DefaultTenantConfigDir, entry.Name())
		tenantConfig, err := loadTenantConfigFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load tenant config %s: %w", entry.Name(), err)
		}

		// Create authenticator
		authenticator := &TenantAuthenticator{
			ldapClient:   ldapClient,
			tenantConfig: tenantConfig,
		}

		registry.authenticators[tenantID] = authenticator
		slog.Info("loaded tenant config", "tenantID", tenantID)
	}

	if len(registry.authenticators) == 0 {
		return nil, fmt.Errorf("no tenant configurations found in %s", DefaultTenantConfigDir)
	}

	slog.Info("tenant registry initialized", "tenantCount", len(registry.authenticators))
	return registry, nil
}

// GetAuthenticator returns the authenticator for a tenant, or error if not found
func (r *TenantRegistry) GetAuthenticator(tenantID string) (*TenantAuthenticator, error) {
	// for safety/double-checking
	if err := validateTenantID(tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenant name %s: %w", tenantID, err)
	}
	auth, exists := r.authenticators[tenantID]
	if !exists {
		return nil, fmt.Errorf("unknown tenant: %s", tenantID)
	}
	return auth, nil
}

// loadTenantConfigFile reads and validates a single tenant config file
func loadTenantConfigFile(path string) (*TenantConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var config TenantConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}

	// Set defaults for optional fields
	if config.UserFilter == "" {
		config.UserFilter = "(cn=%s)" // Standard LDAP default
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &config, nil
}

// validateTenantID prevents path traversal attacks
func validateTenantID(tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	// defensive, should never have to be cleaned up if the keys in cm are ok.
	if strings.Contains(tenantID, "..") || strings.Contains(tenantID, "/") || strings.Contains(tenantID, "\\") {
		return fmt.Errorf("tenant ID contains invalid characters")
	}
	return nil
}
