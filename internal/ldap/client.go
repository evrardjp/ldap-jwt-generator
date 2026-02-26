package ldap

import (
	"fmt"
	"ldap-jwt-generator/internal/user"

	ldap "github.com/go-ldap/ldap/v3"
)

// This is the internal API for LDAP auth.
// The rest of the implementation is in the internal/ldap package.

type LDAPClient struct {
	*BaseConfig
}

func NewLDAPClient(config *BaseConfig) *LDAPClient {
	return &LDAPClient{
		BaseConfig: config,
	}
}

// SearchUsers performs user search in LDAP with explicit parameters
// Takes all parameters explicitly (no tenant info in struct)
func (c *LDAPClient) SearchUsers(baseDN, filter, username string) (*user.Details, error) {
	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := fmt.Sprintf(filter, username)
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2, 10, false,
		searchFilter,
		[]string{"dn", "mail"},
		nil,
	)

	res, err := conn.SearchWithPaging(req, c.PageSize)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("user not found or multiple matches")
	}

	entry := res.Entries[0]
	return &user.Details{
		Name:  username,
		DN:    entry.DN,
		Email: entry.GetAttributeValue("mail"),
	}, nil
}

// SearchGroups performs group search in LDAP with a single baseDN and filter
func (c *LDAPClient) SearchGroups(baseDN, filter, userDN string) ([]*ldap.Entry, error) {
	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := fmt.Sprintf(filter, userDN)

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"cn", "dn"},
		nil,
	)

	res, err := conn.SearchWithPaging(req, c.PageSize)
	if err != nil {
		return nil, err
	}

	return res.Entries, nil
}

// ValidateUserPassword binds as the user to verify password
func (c *LDAPClient) ValidateUserPassword(userDN, password string) error {
	conn, err := c.ldapConnectAndBind(userDN, password)
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	conn.Close()
	return nil
}
