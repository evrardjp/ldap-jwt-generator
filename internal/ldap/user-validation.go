package ldap

import (
	"fmt"
	"ldap-jwt-generator/internal/user"

	"gopkg.in/ldap.v2"
)

// Finds an user and check if its password is correct.
func (c *LDAPClient) validateUserCredentials(base string, impersonateUsername string, impersonatePassword string) (*user.Details, error) {
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, fmt.Sprintf(c.UserFilter, impersonateUsername), []string{"dn", "mail"}, nil)

	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := conn.SearchWithPaging(req, c.PageSize)

	switch {
	case err != nil:
		return nil, fmt.Errorf("error searching for user %s, %w", impersonateUsername, err)
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("no result for the user search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("multiple entries found for the user search filter '%s'", req.Filter)
	}

	userDN := res.Entries[0].DN
	mail := res.Entries[0].GetAttributeValue("mail")
	loggingInUser := &user.Details{
		Username: impersonateUsername,
		UserDN:   userDN,
		Email:    mail,
	}

	_, err = c.ldapConnectAndBind(loggingInUser.UserDN, impersonatePassword)
	if err != nil {
		return nil, fmt.Errorf("cannot authenticate user %s with DN %s in LDAP", loggingInUser.Username, loggingInUser.UserDN)
	}
	return loggingInUser, nil
}
