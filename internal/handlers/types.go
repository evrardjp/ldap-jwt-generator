package middlewares

import "ldap-jwt-generator/internal/user"

type Auth struct {
	Username string
	Password string
}

type contextKey string

const UserContextKey contextKey = "user"

type Authenticator interface {
	AuthN(username, password string) (*user.Details, error)
}

type Authorizer interface {
	AuthZ(user *user.Details) (*user.Details, error)
}
