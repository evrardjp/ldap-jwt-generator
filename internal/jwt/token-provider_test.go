package jwt

// NOTE: This test file has been temporarily disabled during the refactoring from kubi to ldap-jwt-generator.
// The tests need to be rewritten to work with the new architecture:
//
// Old architecture tested (commented out in issuer.go):
// - signJWTClaims()
// - generateUserJWTClaims()
// - generateServiceJWTClaims()
// - TokenIssuer with old fields (EcdsaPrivate, EcdsaPublic, ExtraTokenDuration, Locator, PublicApiServerURL, Tenant)
//
// New architecture to test:
// - GenerateJWT() handler (active implementation)
// - TokenIssuer with new fields (PrivateKey, PublicKey, TokenDuration, IssuerFQDN)
// - New AuthJWTClaims structure (username, email, userDN, tenantId, groups + RegisteredClaims)
// - JWT security claims (iss, aud, exp, nbf, iat, sub, jti)
//
// TODO: Create new tests for the refactored JWT implementation that test:
// 1. Token generation with all required claims
// 2. Token signing with ECDSA-P512
// 3. Token validation with public key
// 4. Proper expiration handling
// 5. JTI generation uniqueness

// Original tests relied on:
// - github.com/ca-gip/kubi/internal/utils (old kubi package)
// - github.com/ca-gip/kubi/pkg/types (old kubi package)
// - github.com/dgrijalva/jwt-go (deprecated JWT library, replaced with golang-jwt/v5)
