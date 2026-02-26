package ldap

import (
	"fmt"
	"ldap-jwt-generator/internal/user"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// MockLDAPClient is a test double for LDAPClient
type MockLDAPClient struct {
	SearchUsersFunc          func(baseDN, filter, username string) (*user.Details, error)
	SearchGroupsFunc         func(baseDN, filter, userDN string) ([]*ldap.Entry, error)
	ValidateUserPasswordFunc func(userDN, password string) error
}

func (m *MockLDAPClient) SearchUsers(baseDN, filter, username string) (*user.Details, error) {
	if m.SearchUsersFunc != nil {
		return m.SearchUsersFunc(baseDN, filter, username)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLDAPClient) SearchGroups(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
	if m.SearchGroupsFunc != nil {
		return m.SearchGroupsFunc(baseDN, filter, userDN)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLDAPClient) ValidateUserPassword(userDN, password string) error {
	if m.ValidateUserPasswordFunc != nil {
		return m.ValidateUserPasswordFunc(userDN, password)
	}
	return fmt.Errorf("not implemented")
}

// mockLDAPClientInterface is an interface for LDAP operations (for testing)
type mockLDAPClientInterface interface {
	SearchUsers(baseDN, filter, username string) (*user.Details, error)
	SearchGroups(baseDN, filter, userDN string) ([]*ldap.Entry, error)
	ValidateUserPassword(userDN, password string) error
}

// testTenantAuthenticator is a test version that uses the mock interface
type testTenantAuthenticator struct {
	client       mockLDAPClientInterface
	tenantConfig *TenantConfig
}

func (ta *testTenantAuthenticator) AuthN(username, password string) (*user.Details, error) {
	userDetails, err := ta.client.SearchUsers(
		ta.tenantConfig.UserBase,
		ta.tenantConfig.UserFilter,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if err := ta.client.ValidateUserPassword(userDetails.DN, password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	return userDetails, nil
}

func (ta *testTenantAuthenticator) AuthZ(userDetails *user.Details) (*user.Details, error) {
	if userDetails == nil {
		return nil, fmt.Errorf("user details cannot be nil")
	}

	groups, err := ta.GetUserGroups(userDetails.DN)
	if err != nil {
		return nil, err
	}

	userDetails.Groups = groups
	return userDetails, nil
}

func (ta *testTenantAuthenticator) GetUserGroups(userDN string) ([]string, error) {
	if userDN == "" {
		return nil, fmt.Errorf("userDN cannot be empty")
	}

	var allGroups []string
	for _, groupSource := range ta.tenantConfig.GroupSources {
		entries, err := ta.client.SearchGroups(
			groupSource.Base,
			groupSource.Filter,
			userDN,
		)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			allGroups = append(allGroups, entry.GetAttributeValue("cn"))
		}
	}

	return allGroups, nil
}

// Tests

func TestAuthN_SuccessfulAuth(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchUsersFunc: func(baseDN, filter, username string) (*user.Details, error) {
			if username == "testuser" {
				return &user.Details{
					Name:  "testuser",
					DN:    "uid=testuser,ou=users,dc=test,dc=com",
					Email: "testuser@test.com",
				}, nil
			}
			return nil, fmt.Errorf("user not found")
		},
		ValidateUserPasswordFunc: func(userDN, password string) error {
			if password == "correctpass" {
				return nil
			}
			return fmt.Errorf("invalid password")
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	userDetails, err := ta.AuthN("testuser", "correctpass")
	if err != nil {
		t.Fatalf("Expected successful auth, got error: %v", err)
	}

	if userDetails.Name != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", userDetails.Name)
	}
	if userDetails.DN != "uid=testuser,ou=users,dc=test,dc=com" {
		t.Errorf("Expected DN 'uid=testuser,ou=users,dc=test,dc=com', got '%s'", userDetails.DN)
	}
}

func TestAuthN_InvalidCredentials(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchUsersFunc: func(baseDN, filter, username string) (*user.Details, error) {
			return &user.Details{
				Name: "testuser",
				DN:   "uid=testuser,ou=users,dc=test,dc=com",
			}, nil
		},
		ValidateUserPasswordFunc: func(userDN, password string) error {
			return fmt.Errorf("invalid password")
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	_, err := ta.AuthN("testuser", "wrongpass")
	if err == nil {
		t.Error("Expected error for invalid password, got nil")
	}
}

func TestAuthN_UserNotFound(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchUsersFunc: func(baseDN, filter, username string) (*user.Details, error) {
			return nil, fmt.Errorf("user not found")
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	_, err := ta.AuthN("nonexistent", "password")
	if err == nil {
		t.Error("Expected error for nonexistent user, got nil")
	}
}

func TestAuthZ_FetchesGroupsFromSingleSource(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchGroupsFunc: func(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
			entry1 := ldap.NewEntry("cn=admin,ou=groups,dc=test,dc=com", map[string][]string{
				"cn": {"admin"},
			})
			entry2 := ldap.NewEntry("cn=developers,ou=groups,dc=test,dc=com", map[string][]string{
				"cn": {"developers"},
			})
			return []*ldap.Entry{entry1, entry2}, nil
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	userDetails := &user.Details{
		Name: "testuser",
		DN:   "uid=testuser,ou=users,dc=test,dc=com",
	}

	enrichedUser, err := ta.AuthZ(userDetails)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(enrichedUser.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(enrichedUser.Groups))
	}

	expectedGroups := []string{"admin", "developers"}
	for _, expected := range expectedGroups {
		found := false
		for _, group := range enrichedUser.Groups {
			if group == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected group '%s' not found in groups", expected)
		}
	}
}

func TestAuthZ_FetchesGroupsFromMultipleSources(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchGroupsFunc: func(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
			if baseDN == "ou=groups,dc=test,dc=com" {
				entry := ldap.NewEntry("cn=group1,ou=groups,dc=test,dc=com", map[string][]string{
					"cn": {"group1"},
				})
				return []*ldap.Entry{entry}, nil
			}
			if baseDN == "ou=roles,dc=test,dc=com" {
				entry := ldap.NewEntry("cn=role1,ou=roles,dc=test,dc=com", map[string][]string{
					"cn": {"role1"},
				})
				return []*ldap.Entry{entry}, nil
			}
			return nil, nil
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
				{Base: "ou=roles,dc=test,dc=com", Filter: "(uniqueMember=%s)"},
			},
		},
	}

	userDetails := &user.Details{
		Name: "testuser",
		DN:   "uid=testuser,ou=users,dc=test,dc=com",
	}

	enrichedUser, err := ta.AuthZ(userDetails)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(enrichedUser.Groups) != 2 {
		t.Errorf("Expected 2 groups from different sources, got %d", len(enrichedUser.Groups))
	}
}

func TestAuthZ_EmptyGroups(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchGroupsFunc: func(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
			return []*ldap.Entry{}, nil // No groups found
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	userDetails := &user.Details{
		Name: "testuser",
		DN:   "uid=testuser,ou=users,dc=test,dc=com",
	}

	enrichedUser, err := ta.AuthZ(userDetails)
	if err != nil {
		t.Fatalf("Expected no error for user with no groups, got %v", err)
	}

	if len(enrichedUser.Groups) != 0 {
		t.Errorf("Expected 0 groups, got %d", len(enrichedUser.Groups))
	}
}

func TestAuthZ_NilUserDetails(t *testing.T) {
	ta := &testTenantAuthenticator{
		client: &MockLDAPClient{},
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	_, err := ta.AuthZ(nil)
	if err == nil {
		t.Error("Expected error for nil user details, got nil")
	}
	if err.Error() != "user details cannot be nil" {
		t.Errorf("Expected error 'user details cannot be nil', got '%v'", err)
	}
}

func TestAuthZ_ErrorHandling(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchGroupsFunc: func(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
			return nil, fmt.Errorf("LDAP connection error")
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	userDetails := &user.Details{
		Name: "testuser",
		DN:   "uid=testuser,ou=users,dc=test,dc=com",
	}

	// Despite error, AuthZ should continue and return empty groups
	enrichedUser, err := ta.AuthZ(userDetails)
	if err != nil {
		t.Fatalf("Expected no error (errors are logged but not returned), got %v", err)
	}
	if len(enrichedUser.Groups) != 0 {
		t.Errorf("Expected 0 groups when all sources fail, got %d", len(enrichedUser.Groups))
	}
}

func TestGetUserGroups_EmptyUserDN(t *testing.T) {
	ta := &testTenantAuthenticator{
		client: &MockLDAPClient{},
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
			},
		},
	}

	_, err := ta.GetUserGroups("")
	if err == nil {
		t.Error("Expected error for empty userDN, got nil")
	}
	if err.Error() != "userDN cannot be empty" {
		t.Errorf("Expected error 'userDN cannot be empty', got '%v'", err)
	}
}

func TestGetUserGroups_PartialFailure(t *testing.T) {
	mockClient := &MockLDAPClient{
		SearchGroupsFunc: func(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
			// First source succeeds
			if baseDN == "ou=groups,dc=test,dc=com" {
				entry := ldap.NewEntry("cn=group1,ou=groups,dc=test,dc=com", map[string][]string{
					"cn": {"group1"},
				})
				return []*ldap.Entry{entry}, nil
			}
			// Second source fails
			if baseDN == "ou=roles,dc=test,dc=com" {
				return nil, fmt.Errorf("connection timeout")
			}
			return nil, nil
		},
	}

	ta := &testTenantAuthenticator{
		client: mockClient,
		tenantConfig: &TenantConfig{
			UserBase:   "ou=users,dc=test,dc=com",
			UserFilter: "(uid=%s)",
			GroupSources: []GroupSource{
				{Base: "ou=groups,dc=test,dc=com", Filter: "(member=%s)"},
				{Base: "ou=roles,dc=test,dc=com", Filter: "(uniqueMember=%s)"},
			},
		},
	}

	groups, err := ta.GetUserGroups("uid=testuser,ou=users,dc=test,dc=com")
	if err != nil {
		t.Fatalf("Expected no error (partial failures are handled), got %v", err)
	}

	// Should have 1 group from successful source
	if len(groups) != 1 {
		t.Errorf("Expected 1 group from successful source, got %d", len(groups))
	}
	if groups[0] != "group1" {
		t.Errorf("Expected group 'group1', got '%s'", groups[0])
	}
}
