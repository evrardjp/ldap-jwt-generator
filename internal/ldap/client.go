package ldap

import (
	"fmt"
	ldap "github.com/go-ldap/ldap/v3"
	"ldap-jwt-generator/internal/user"
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
		Username: username,
		UserDN:   entry.DN,
		Email:    entry.GetAttributeValue("mail"),
	}, nil
}

// SearchGroups performs group search in LDAP
func (c *LDAPClient) SearchGroups(baseDNs []string, filter, userDN string) ([]*ldap.Entry, error) {
	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var allEntries []*ldap.Entry
	searchFilter := fmt.Sprintf(filter, userDN)

	for _, baseDN := range baseDNs {
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
			continue // Skip this base if search fails
		}

		allEntries = append(allEntries, res.Entries...)
	}

	return allEntries, nil
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

//
//func (c *LDAPClient) AuthZ(user *types.User) (*types.User, error) {
//	// Get User Memberships
//	if user == nil {
//		return &types.User{}, fmt.Errorf("cannot get memberships for nil user")
//	}
//	if user.Email == "" || user.UserDN == "" || user.Username == "" {
//		return &types.User{}, fmt.Errorf("cannot get memberships for empty user %v in LDAP", user)
//	}
//
//	// to keep for historical reasons: We continue to issue tokens with old data until
//	// ArgoCD + promote + other? is updated to use the new groups.
//	// When migration is over, we can simplify the User struct and remove the old fields.
//
//	ldapMemberships, err := c.getMemberships(user.UserDN)
//	if err != nil {
//		return &types.User{}, fmt.Errorf("cannot get memberships for user %s in LDAP, %v", user.Username, err)
//	}
//
//	slog.Debug("listing user groups", "user", user.Username, "groups", ldapMemberships.toGroupNames())
//
//	// We now have all the user details (including special groups).
//	// we can check if the user has the basic right to get a token.
//	// If they do, it means we trust the user, and we'll rely on the authorization db of each asset
//	// (dex+kubi plugin+argocm for argcd, kubernetes+kubiwebhook+rolebindings for kube api, promote...)
//
//	allowedInCluster := ldapMemberships.isUserAllowedOnCluster()
//
//	if !allowedInCluster {
//		return nil, fmt.Errorf("user is not allowed in this cluster %v", user.UserDN)
//	}
//
//	// now create the user data accordingly.
//	user.Groups = ldapMemberships.toGroupNames()
//
//	// To be removed in final stage
//	user.IsAdmin = len(ldapMemberships.AdminAccess) > 0
//	user.IsAppOps = (len(ldapMemberships.AppOpsAccess) > 0) || (len(ldapMemberships.CustomerOpsAccess) > 0)
//	user.IsCloudOps = len(ldapMemberships.CloudOpsAccess) > 0
//	user.IsViewer = len(ldapMemberships.ViewerAccess) > 0
//	user.IsService = len(ldapMemberships.ServiceAccess) > 0
//	user.ProjectAccesses = ldapMemberships.toProjectNames()
//
//	return user, nil
//}
