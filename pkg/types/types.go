package types

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AuthJWTClaims struct {
	Auths             []*Project `json:"auths"`
	User              string     `json:"user"`
	Groups            []string   `json:"groups"`
	Contact           string     `json:"email"`
	AdminAccess       bool       `json:"adminAccess"`
	ApplicationAccess bool       `json:"appAccess"`
	OpsAccess         bool       `json:"opsAccess"`
	ViewerAccess      bool       `json:"viewerAccess"`
	ServiceAccess     bool       `json:"serviceAccess"`
	Locator           string     `json:"locator"`
	Endpoint          string     `json:"endPoint"`
	Tenant            string     `json:"tenant"`
	Scopes            string     `json:"scopes"`
	jwt.StandardClaims
}

type Project struct {
	Project     string `json:"project"`
	Role        string `json:"role"`
	Source      string `json:"-"`
	Environment string `json:"environment"`
	Contact     string `json:"-"`
}

func (project *Project) Namespace() (ns string) {
	if len(project.Environment) > 0 {
		ns = fmt.Sprintf("%s-%s", project.Project, project.Environment)
	} else {
		ns = project.Project
	}
	return
}

type ResponseError struct {
	metav1.TypeMeta
	metav1.Status
}

type BlackWhitelist struct {
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
}

type User struct {
	Username        string
	UserDN          string
	Email           string
	Groups          []string // Store alls the user groups (search is based on implementation!), including the ProjectAccess groups
	IsAdmin         bool
	IsAppOps        bool
	IsCloudOps      bool
	IsViewer        bool
	IsService       bool
	ProjectAccesses []string // Contains the groups matching the cluster's project naming convention. Purposedly a string instead of a []*Project: This will allow the testing based on the project names instead of projects, but also makes it a very clean separation between the ldap package, and its implementation. This will allow further cleanup should another method be used later.
}
