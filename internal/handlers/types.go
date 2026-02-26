package handlers

import (
	"ldap-jwt-generator/internal/user"
)

type Auth struct {
	Username string
	Password string
}

type contextKey string

const UserContextKey contextKey = "user"

// Authenticator must validate the user is valid
type Authenticator interface {
	AuthN(username, password string) (*user.Details, error)
}

// Authorizer must validate the user is allowed to connect to this API and enrich the user.Details with their authorizations for other APIs
type Authorizer interface {
	AuthZ(user *user.Details) (*user.Details, error)
}
