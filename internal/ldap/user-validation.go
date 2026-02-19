package ldap

// NOTE: validateUserCredentials() method removed - functionality replaced by
// TenantAuthenticator.AuthN() in tenant-registry.go which calls low-level
// ldapClient.SearchUsers() and ldapClient.ValidateUserPassword() methods
