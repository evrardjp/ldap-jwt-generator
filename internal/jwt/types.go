package jwt

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	PublicKeyLocation  = "/etc/ldap-jwt-generator/signing-keys/ecdsa-public-key.pem"
	PrivateKeyLocation = "/etc/ldap-jwt-generator/signing-keys/ecdsa-private-key.pem"
)

type TokenIssuer struct {
	PrivateKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
	TokenDuration time.Duration
	IssuerFQDN    string
}

// AuthJWTClaims represents the JWT token claims
type AuthJWTClaims struct {
	// Custom claims
	User    string   `json:"user"`
	Contact string   `json:"contact"`
	UserDN  string   `json:"userDN"`
	Tenant  string   `json:"tenant"`
	Groups  []string `json:"groups"`

	// Standard JWT claims (iss, aud, exp, nbf, iat, sub, jti)
	jwt.RegisteredClaims
}

func NewTokenIssuer() (*TokenIssuer, error) {
	defaultDuration := os.Getenv("TOKEN_LIFETIME")
	if defaultDuration == "" {
		defaultDuration = "4h"
	}

	// Load issuer FQDN from environment
	issuerFQDN := os.Getenv("JWT_ISSUER_FQDN")
	if issuerFQDN == "" {
		return nil, fmt.Errorf("JWT_ISSUER_FQDN environment variable is required")
	}

	duration, err := time.ParseDuration(defaultDuration)
	if err != nil {
		return nil, fmt.Errorf("unable to parse duration %s", defaultDuration)
	}

	if _, errStat := os.Stat(PrivateKeyLocation); os.IsNotExist(errStat) {
		return nil, errStat
	}

	if _, errStat := os.Stat(PublicKeyLocation); os.IsNotExist(errStat) {
		return nil, errStat
	}

	privatePEM, errPrivateKey := os.ReadFile(PrivateKeyLocation)
	if errPrivateKey != nil {
		return nil, fmt.Errorf("unable to read ECDSA private key %w", errPrivateKey)
	}
	publicPEM, errPublicKey := os.ReadFile(PublicKeyLocation)
	if errPublicKey != nil {
		return nil, fmt.Errorf("unable to read ECDSA public key %w", errPublicKey)
	}

	var ecdsaPrivateKey *ecdsa.PrivateKey
	var ecdsaPublicKey *ecdsa.PublicKey
	if ecdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(privatePEM); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPublicKey, err = jwt.ParseECPublicKeyFromPEM(publicPEM); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA public key: %v", err)
	}

	return &TokenIssuer{
		PrivateKey:    ecdsaPrivateKey,
		PublicKey:     ecdsaPublicKey,
		TokenDuration: duration,
		IssuerFQDN:    issuerFQDN,
	}, nil
}
