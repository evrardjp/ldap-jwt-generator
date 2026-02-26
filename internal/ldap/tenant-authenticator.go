package ldap

import (
	"fmt"
	"ldap-jwt-generator/internal/user"
	"log/slog"
)

// TenantAuthenticator combines base LDAP config with tenant-specific config
type TenantAuthenticator struct {
	ldapClient   *LDAPClient
	tenantConfig *TenantConfig
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

	var allGroups []string

	// Iterate over each GroupSource and aggregate results
	for _, groupSource := range ta.tenantConfig.GroupSources {
		entries, err := ta.ldapClient.SearchGroups(
			groupSource.Base,
			groupSource.Filter,
			userDN,
		)
		if err != nil {
			slog.Debug("failed to search groups for source",
				"base", groupSource.Base,
				"filter", groupSource.Filter,
				"error", err)
			continue // Skip this source if search fails
		}

		for _, entry := range entries {
			allGroups = append(allGroups, entry.GetAttributeValue("cn"))
		}
	}

	slog.Debug("fetched user groups",
		"sourceCount", len(ta.tenantConfig.GroupSources),
		"userDN", userDN,
		"groupCount", len(allGroups))

	return allGroups, nil
}
