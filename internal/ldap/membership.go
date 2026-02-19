package ldap

import (
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// THIS NEEDS A GOOD REFACTORING.

type LDAPMemberships struct {
	AdminAccess         []*ldap.Entry // Contains the groups considered for admin, to be removed in the future
	AppOpsAccess        []*ldap.Entry
	CustomerOpsAccess   []*ldap.Entry
	ViewerAccess        []*ldap.Entry
	ServiceAccess       []*ldap.Entry
	CloudOpsAccess      []*ldap.Entry
	ClusterGroupsAccess []*ldap.Entry // This represents the groups that are cluster-scoped (=projects)
	NonSpecificGroups   []*ldap.Entry // This contains all the non-specific and non-project groups, unfiltered.
}

// NOTE: getMemberships() method removed - functionality moved to TenantAuthenticator.categorizeGroups()
// in tenant-registry.go as part of clean architecture refactoring

// toGroupNames returns a slice for all the group names (DN) the user is member of,
// rather than their full LDAP entries.
// Ensuring uniqueness through map of 0 bytes structs as sets do not exist in go std lib
// This is necessary, because we know the groups in specific access (like adminAccess)
// are also present in the big blob of groups (="NonSpecificGroups")
func (m *LDAPMemberships) toGroupNames() []string {
	groupMap := make(map[string]struct{})

	accessCategories := [][]*ldap.Entry{
		m.AdminAccess,
		m.AppOpsAccess,
		m.CustomerOpsAccess,
		m.ViewerAccess,
		m.ServiceAccess,
		m.CloudOpsAccess,
		m.ClusterGroupsAccess,
		m.NonSpecificGroups,
	}

	for _, category := range accessCategories {
		for _, entry := range category {
			normalizedGroup := strings.ToUpper(entry.GetAttributeValue("cn"))
			groupMap[normalizedGroup] = struct{}{}
		}
	}

	groups := make([]string, 0, len(groupMap))
	for group := range groupMap {
		groups = append(groups, group)
	}

	return groups
}

// toProjectNames retuns a slice for all the project names the user is member of,
// rather than their full LDAP entries. This is not returning a slice of the projects.
func (m *LDAPMemberships) toProjectNames() []string {
	var groups []string
	for _, entry := range m.ClusterGroupsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups
}

func (m *LDAPMemberships) isUserAllowedOnCluster() bool {
	// To get access, the user needs at least one of the following:
	return (len(m.AdminAccess) > 0 || // - Have special rights
		len(m.AppOpsAccess) > 0 || // - Have special rights
		len(m.CustomerOpsAccess) > 0 || // - Have special rights
		len(m.ViewerAccess) > 0 || // - Have special rights
		len(m.ServiceAccess) > 0 || // - Have special rights
		len(m.CloudOpsAccess) > 0 || // - Have special rights
		len(m.ClusterGroupsAccess) > 0 || //- Be granted access to at least one project
		len(m.NonSpecificGroups) > 0) // Be member of a group eligible to rolebindings
}
