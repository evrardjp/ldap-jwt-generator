package ldap

import (
	"os"
	"testing"
)

func TestNewLDAPBaseConfig_ValidEnvironment(t *testing.T) {
	// Set up valid environment variables
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	os.Setenv("LDAP_PAGE_SIZE", "500")
	defer cleanupEnv()

	config, err := NewLDAPBaseConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if config.Host != "ldap.example.com" {
		t.Errorf("Expected host 'ldap.example.com', got '%s'", config.Host)
	}
	if config.Port != 389 {
		t.Errorf("Expected port 389, got %d", config.Port)
	}
	if config.BindDN != "cn=admin,dc=example,dc=com" {
		t.Errorf("Expected BindDN 'cn=admin,dc=example,dc=com', got '%s'", config.BindDN)
	}
	if config.BindPassword != "secretpassword" {
		t.Errorf("Expected BindPassword 'secretpassword', got '%s'", config.BindPassword)
	}
	if config.PageSize != 500 {
		t.Errorf("Expected PageSize 500, got %d", config.PageSize)
	}
	// Port 389 without insecure should enable StartTLS
	if !config.StartTLS {
		t.Error("Expected StartTLS to be true for port 389")
	}
	if config.UseSSL {
		t.Error("Expected UseSSL to be false for port 389")
	}
	if !config.TLSVerification {
		t.Error("Expected TLSVerification to be true")
	}
}

func TestNewLDAPBaseConfig_Port636_SSL(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "636")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	config, err := NewLDAPBaseConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if config.Port != 636 {
		t.Errorf("Expected port 636, got %d", config.Port)
	}
	// Port 636 should not use StartTLS (direct SSL)
	if config.StartTLS {
		t.Error("Expected StartTLS to be false for port 636")
	}
	if config.UseSSL {
		t.Error("Expected UseSSL to be false for port 636")
	}
	if !config.TLSVerification {
		t.Error("Expected TLSVerification to be true")
	}
}

func TestNewLDAPBaseConfig_CustomPort(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "10389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	config, err := NewLDAPBaseConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if config.Port != 10389 {
		t.Errorf("Expected port 10389, got %d", config.Port)
	}
}

func TestNewLDAPBaseConfig_InsecureMode(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	os.Setenv("INSECURE_LDAP", "true")
	defer cleanupEnv()

	config, err := NewLDAPBaseConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Insecure mode should disable TLS features
	if config.StartTLS {
		t.Error("Expected StartTLS to be false in insecure mode")
	}
	if config.UseSSL {
		t.Error("Expected UseSSL to be false in insecure mode")
	}
	if config.TLSVerification {
		t.Error("Expected TLSVerification to be false in insecure mode")
	}
}

func TestNewLDAPBaseConfig_DefaultPageSize(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	// Don't set LDAP_PAGE_SIZE
	defer cleanupEnv()

	config, err := NewLDAPBaseConfig()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if config.PageSize != 1000 {
		t.Errorf("Expected default PageSize 1000, got %d", config.PageSize)
	}
}

func TestNewLDAPBaseConfig_MissingServer(t *testing.T) {
	// Don't set LDAP_SERVER
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for missing LDAP_SERVER, got nil")
	}
	if err.Error() != "host is required" {
		t.Errorf("Expected error 'host is required', got '%v'", err)
	}
}

func TestNewLDAPBaseConfig_EmptyPort(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for empty LDAP_PORT, got nil")
	}
}

func TestNewLDAPBaseConfig_InvalidPort(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "not-a-number")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for invalid LDAP_PORT, got nil")
	}
}

func TestNewLDAPBaseConfig_InvalidInsecureFlag(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	os.Setenv("INSECURE_LDAP", "not-a-bool")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for invalid INSECURE_LDAP, got nil")
	}
}

func TestNewLDAPBaseConfig_MissingBindDN(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	// Don't set LDAP_BINDDN
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for missing LDAP_BINDDN, got nil")
	}
}

func TestNewLDAPBaseConfig_BindDNTooShort(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "x") // Too short (< 2 chars)
	os.Setenv("LDAP_PASSWD", "secretpassword")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for LDAP_BINDDN too short, got nil")
	}
}

func TestNewLDAPBaseConfig_MissingPassword(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	// Don't set LDAP_PASSWD
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for missing LDAP_PASSWD, got nil")
	}
}

func TestNewLDAPBaseConfig_PasswordTooShort(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "x") // Too short (< 2 chars)
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for LDAP_PASSWD too short, got nil")
	}
}

func TestNewLDAPBaseConfig_InvalidPageSize(t *testing.T) {
	os.Setenv("LDAP_SERVER", "ldap.example.com")
	os.Setenv("LDAP_PORT", "389")
	os.Setenv("LDAP_BINDDN", "cn=admin,dc=example,dc=com")
	os.Setenv("LDAP_PASSWD", "secretpassword")
	os.Setenv("LDAP_PAGE_SIZE", "not-a-number")
	defer cleanupEnv()

	_, err := NewLDAPBaseConfig()
	if err == nil {
		t.Error("Expected error for invalid LDAP_PAGE_SIZE, got nil")
	}
}

// TenantConfig.Validate() tests

func TestTenantConfig_Validate_Valid(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "(member=%s)",
			},
		},
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Expected no error for valid config, got %v", err)
	}
}

func TestTenantConfig_Validate_MultipleGroupSources(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "(member=%s)",
			},
			{
				Base:   "ou=roles,dc=example,dc=com",
				Filter: "(uniqueMember=%s)",
			},
		},
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Expected no error for valid config with multiple group sources, got %v", err)
	}
}

func TestTenantConfig_Validate_MissingUserBase(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "", // Missing
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "(member=%s)",
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing userBase, got nil")
	}
	if err.Error() != "userBase is required" {
		t.Errorf("Expected error 'userBase is required', got '%v'", err)
	}
}

func TestTenantConfig_Validate_MissingUserFilter(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "", // Missing
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "(member=%s)",
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing userFilter, got nil")
	}
	if err.Error() != "userFilter is required" {
		t.Errorf("Expected error 'userFilter is required', got '%v'", err)
	}
}

func TestTenantConfig_Validate_EmptyGroupSources(t *testing.T) {
	config := &TenantConfig{
		UserBase:     "ou=users,dc=example,dc=com",
		UserFilter:   "(uid=%s)",
		GroupSources: []GroupSource{}, // Empty
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for empty groupSources, got nil")
	}
	if err.Error() != "groupSources is required and must have at least one entry" {
		t.Errorf("Expected error 'groupSources is required and must have at least one entry', got '%v'", err)
	}
}

func TestTenantConfig_Validate_GroupSourceMissingBase(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "", // Missing
				Filter: "(member=%s)",
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing groupSource base, got nil")
	}
	if err.Error() != "groupSources[0].base is required" {
		t.Errorf("Expected error 'groupSources[0].base is required', got '%v'", err)
	}
}

func TestTenantConfig_Validate_GroupSourceMissingFilter(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "", // Missing
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing groupSource filter, got nil")
	}
	if err.Error() != "groupSources[0].filter is required" {
		t.Errorf("Expected error 'groupSources[0].filter is required', got '%v'", err)
	}
}

func TestTenantConfig_Validate_SecondGroupSourceInvalid(t *testing.T) {
	config := &TenantConfig{
		UserBase:   "ou=users,dc=example,dc=com",
		UserFilter: "(uid=%s)",
		GroupSources: []GroupSource{
			{
				Base:   "ou=groups,dc=example,dc=com",
				Filter: "(member=%s)",
			},
			{
				Base:   "", // Missing in second source
				Filter: "(uniqueMember=%s)",
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for invalid second groupSource, got nil")
	}
	if err.Error() != "groupSources[1].base is required" {
		t.Errorf("Expected error 'groupSources[1].base is required', got '%v'", err)
	}
}

// Helper function to clean up environment variables
func cleanupEnv() {
	os.Unsetenv("LDAP_SERVER")
	os.Unsetenv("LDAP_PORT")
	os.Unsetenv("LDAP_BINDDN")
	os.Unsetenv("LDAP_PASSWD")
	os.Unsetenv("LDAP_PAGE_SIZE")
	os.Unsetenv("INSECURE_LDAP")
}
