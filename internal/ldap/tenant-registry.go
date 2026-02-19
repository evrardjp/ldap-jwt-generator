package ldap

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"ldap-jwt-generator/internal/user"
)

const DefaultTenantConfigDir = "/etc/ldap-configs"

// TenantRegistryInterface defines the interface for tenant registry (for testing)
type TenantRegistryInterface interface {
	GetAuthenticator(tenantID string) (*TenantAuthenticator, error)
}

// TenantAuthenticator combines base LDAP config with tenant-specific config
type TenantAuthenticator struct {
	TenantID     string
	ldapClient   *LDAPClient
	tenantConfig *TenantConfig
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
			TenantID:     tenantID,
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
	if config.GroupFilter == "" {
		config.GroupFilter = "(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))"
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
	if strings.Contains(tenantID, "..") || strings.Contains(tenantID, "/") || strings.Contains(tenantID, "\\") {
		return fmt.Errorf("tenant ID contains invalid characters")
	}
	return nil
}

// AuthN authenticates a user with username/password using tenant-specific config
func (ta *TenantAuthenticator) AuthN(username, password string) (*user.Details, error) {
	// Step 1: Search for user in tenant's UserBase
	userDetails, err := ta.ldapClient.SearchUsers(
		ta.tenantConfig.UserBase,
		ta.tenantConfig.UserFilter,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Step 2: Validate password by binding as user
	if err := ta.ldapClient.ValidateUserPassword(userDetails.UserDN, password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	return userDetails, nil
}

// AuthZ fetches user groups and enriches the user object
func (ta *TenantAuthenticator) AuthZ(userDetails *user.Details) (*user.Details, error) {
	if userDetails == nil {
		return nil, fmt.Errorf("user details cannot be nil")
	}

	groups, err := ta.GetUserGroups(userDetails.UserDN)
	if err != nil {
		return nil, err
	}

	// Enrich user with groups
	userDetails.Groups = groups

	return userDetails, nil
}

// GetUserGroups fetches all groups for a user using tenant-specific config
func (ta *TenantAuthenticator) GetUserGroups(userDN string) ([]string, error) {
	if userDN == "" {
		return nil, fmt.Errorf("userDN cannot be empty")
	}

	// Search for all groups containing the user
	// Uses tenant's EligibleGroupsParents and GroupFilter
	entries, err := ta.ldapClient.SearchGroups(
		ta.tenantConfig.EligibleGroupsParents,
		ta.tenantConfig.GroupFilter,
		userDN,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search groups: %w", err)
	}

	// Categorize groups based on tenant's special group bases
	memberships := ta.categorizeGroups(entries)

	// Convert to group names (CN values)
	groups := memberships.toGroupNames()

	slog.Debug("fetched user groups",
		"tenant", ta.TenantID,
		"userDN", userDN,
		"groupCount", len(groups))

	return groups, nil
}

// categorizeGroups sorts LDAP entries into categories based on their DNs
func (ta *TenantAuthenticator) categorizeGroups(entries []*ldap.Entry) *LDAPMemberships {
	m := &LDAPMemberships{}

	// Map of group base DN to membership category
	groupMapping := map[string]*[]*ldap.Entry{
		strings.ToUpper(ta.tenantConfig.AdminGroupBase):       &m.AdminAccess,
		strings.ToUpper(ta.tenantConfig.AppMasterGroupBase):   &m.AppOpsAccess,
		strings.ToUpper(ta.tenantConfig.CustomerOpsGroupBase): &m.CustomerOpsAccess,
		strings.ToUpper(ta.tenantConfig.ViewerGroupBase):      &m.ViewerAccess,
		strings.ToUpper(ta.tenantConfig.ServiceGroupBase):     &m.ServiceAccess,
		strings.ToUpper(ta.tenantConfig.OpsMasterGroupBase):   &m.CloudOpsAccess,
	}

	// Categorize each entry
	for _, entry := range entries {
		upperDN := strings.ToUpper(entry.DN)
		categorized := false

		// Check if entry belongs to a special group category
		for groupBase, categoryList := range groupMapping {
			if groupBase != "" && strings.HasSuffix(upperDN, groupBase) {
				*categoryList = append(*categoryList, entry)
				categorized = true
				break
			}
		}

		// If not categorized, check if it's a cluster/project group
		if !categorized {
			if ta.tenantConfig.GroupBase != "" && strings.HasSuffix(upperDN, strings.ToUpper(ta.tenantConfig.GroupBase)) {
				m.ClusterGroupsAccess = append(m.ClusterGroupsAccess, entry)
			} else {
				m.NonSpecificGroups = append(m.NonSpecificGroups, entry)
			}
		}
	}

	return m
}
