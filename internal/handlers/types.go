package handlers

import (
	"context"
	"ldap-jwt-generator/internal/user"
)

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

// Helper functions for testing
func WithUserInContext(ctx context.Context, userDetails *user.Details) context.Context {
	return context.WithValue(ctx, UserContextKey, userDetails)
}

func WithTenantIDInContext(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}
