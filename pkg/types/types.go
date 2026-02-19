package types

import (
	"github.com/dgrijalva/jwt-go"
)

type AuthJWTClaims struct {
	//Auths             []*Project `json:"auths"`
	User              string   `json:"user"`
	Groups            []string `json:"groups"`
	Contact           string   `json:"email"`
	AdminAccess       bool     `json:"adminAccess"`
	ApplicationAccess bool     `json:"appAccess"`
	OpsAccess         bool     `json:"opsAccess"`
	ViewerAccess      bool     `json:"viewerAccess"`
	ServiceAccess     bool     `json:"serviceAccess"`
	Locator           string   `json:"locator"`
	Endpoint          string   `json:"endPoint"`
	Tenant            string   `json:"tenant"`
	Scopes            string   `json:"scopes"`
	jwt.StandardClaims
}
