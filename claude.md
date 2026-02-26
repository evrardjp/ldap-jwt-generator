# Claude.md - Development Instructions for ldap-jwt-generator

This document provides comprehensive guidance for Claude Code when assisting with development of the ldap-jwt-generator project.

## Project Architecture

### Overview

`ldap-jwt-generator` is an LDAP-to-JWT authentication bridge microservice written in Go. It validates user credentials against LDAP directory services, retrieves group memberships, and issues signed JWT tokens containing user identity and authorization claims.

### Tech Stack

- **Language**: Go 1.26
- **LDAP Client**: `github.com/go-ldap/ldap/v3` v3.4.12
- **JWT Libraries**:
  - `github.com/golang-jwt/jwt/v5` v5.3.1 (primary)
  - `github.com/dgrijalva/jwt-go` v3.2.0 (legacy support)
- **Metrics**: `github.com/prometheus/client_golang` v1.23.2
- **Kubernetes**: `k8s.io/client-go` v0.35.1, `k8s.io/apimachinery` v0.35.1
- **Testing**: Standard Go testing package (NOT Ginkgo/Gomega)
- **Build Tools**: mise task runner, Docker, GoReleaser

### Directory Structure

```
ldap-jwt-generator/
├── cmd/
│   └── main.go                 # Application entry point, HTTP server setup
├── internal/
│   ├── handlers/               # HTTP middleware chain
│   │   ├── tenant.go          # WithTenantConfig: Extract & validate Tenant-Id header
│   │   ├── basicauth.go       # WithBasicAuth: HTTP Basic Auth validation via LDAP
│   │   ├── authorization.go   # WithGroupEnrichment: Fetch user groups, validate membership
│   │   ├── prometheus.go      # Prometheus metrics middleware
│   │   └── types.go           # Handler interfaces & context keys
│   ├── ldap/                  # LDAP integration layer
│   │   ├── client.go          # LDAP connection & query functions
│   │   ├── tenant-registry.go # Multi-tenant LDAP config loader
│   │   ├── tenant-authenticator.go # AuthN (bind) & AuthZ (groups) implementation
│   │   ├── calls.go           # LDAP utility functions
│   │   ├── types.go           # LDAPConfig, TenantConfig structures
│   │   └── metrics.go         # LDAP operation metrics
│   ├── jwt/                   # JWT token generation
│   │   ├── issuer.go          # Token creation & ECDSA-P512 signing
│   │   ├── types.go           # TokenIssuer & AuthJWTClaims
│   │   └── metrics.go         # Token generation metrics
│   └── user/
│       └── types.go           # User model (Name, DN, Email, Groups)
├── pkg/                        # Generated Kubernetes types
├── test/
│   ├── e2e/                   # End-to-end tests with real LDAP
│   │   ├── e2e_suite_test.go
│   │   ├── token_e2e_test.go  # Real LDAP integration tests
│   │   └── token_mock_test.go # Mock-based unit tests
│   └── fixtures/              # Test data & configurations
│       ├── tenant-configs/    # Tenant configuration JSONs
│       ├── ldif/             # LDAP test data (test-data.ldif)
│       └── signing-keys/     # ECDSA test keypair
├── deployments/               # Kubernetes deployment manifests
├── docs/                      # Architecture diagrams
├── mise.toml                  # Task automation configuration
├── go.mod, go.sum            # Go dependency management
├── Dockerfile                # Multi-stage Docker build
├── CONTRIBUTING.md           # Development guide
└── README.md                 # User-facing documentation
```

**Total codebase:** ~3,628 lines of Go code across 58 files

### Request Flow (Middleware Chain)

When a request arrives at `GET /token`, it flows through the following middleware chain:

1. **WithTenantConfig** (`internal/handlers/tenant.go`)
   - Extracts `Tenant-Id` header from request
   - Validates tenant exists in registry (loaded from JSON config files)
   - Stores TenantConfig in request context
   - Returns 404 if tenant not found

2. **WithBasicAuth** (`internal/handlers/basicauth.go`)
   - Parses HTTP Basic Authentication header
   - Calls `AuthN()` on LDAPAuthenticator (LDAP Bind operation)
   - Validates username/password against LDAP server
   - Stores authenticated User in request context
   - Returns 401 if authentication fails

3. **WithGroupEnrichment** (`internal/handlers/authorization.go`)
   - Calls `AuthZ()` on LDAPAuthenticator (LDAP Search for groups)
   - Fetches all groups user belongs to based on tenant config
   - Validates user belongs to at least one group
   - Updates User object with groups
   - Returns 403 if user has no group memberships

4. **GenerateJWT** (final handler in `cmd/main.go`)
   - Creates JWT token with TokenIssuer
   - Includes custom claims: user, contact, userDN, tenant, groups
   - Includes standard JWT claims: iss, sub, aud, exp, nbf, iat, jti
   - Signs token with ECDSA-P512 private key
   - Returns 201 with token as plain text response body

**Key point:** Each middleware extracts/validates data and passes it via request context (though we avoid adding new context keys - see Code Patterns section).

## Development Workflows

### Starting Development

**Always start with a test case** (TDD approach):
1. Write a failing test that demonstrates the desired behavior
2. Implement the minimal code to make the test pass
3. Refactor if needed
4. Run `mise task run test:all` before committing

### Common Mise Tasks

| Task | Description | Command |
|------|-------------|---------|
| **Build** | Compile binary & Docker image | `mise task run build` |
| **Test: Lint** | Run code linters | `mise task run test:lint` |
| **Test: Unit** | Run unit tests with coverage | `mise task run test:unit` |
| **Test: E2E** | Run end-to-end tests | `mise task run test:e2e` |
| **Test: All** | Run complete test suite | `mise task run test:all` |
| **Dev: LDAP Start** | Start OpenLDAP container | `mise task run dev:ldap:start` |
| **Dev: LDAP Stop** | Stop OpenLDAP container | `mise task run dev:ldap:stop` |
| **Dev: API Start** | Start API container | `mise task run dev:api:start` |
| **Dev: API Stop** | Stop API container | `mise task run dev:api:stop` |
| **Dev: Logs** | View container logs | `mise task run dev:logs` |
| **Clean** | Remove build artifacts | `mise task run clean` |
| **Tag Git** | Tag repository | `mise task run tag:git -- v1.0.0` |

### Testing Strategy

**Test Structure:**
- **Unit tests**: Co-located with source files (`*_test.go`)
  - Fast, isolated tests using mocks
  - Test individual functions and methods
  - No external dependencies (no real LDAP, no Docker)
- **E2E tests**: In `test/e2e/` directory
  - Full integration tests with real OpenLDAP container
  - Validate complete authentication flows
  - Test actual LDAP bind and search operations

**Test Fixtures:**
- `test/fixtures/ldif/test-data.ldif` - LDAP entries for testing
  - Pre-defined users: `admin-kube1`, `developer1`, etc.
  - Pre-defined groups with member relationships
- `test/fixtures/tenant-configs/*.json` - Tenant configurations for tests
- `test/fixtures/signing-keys/` - Test ECDSA keypair

**Testing Guidelines:**
- Always test authentication flows end-to-end when modifying auth logic
- Test both success and failure paths (valid credentials, invalid credentials, missing groups, etc.)
- Use table-driven tests where appropriate for testing multiple scenarios
- Mock LDAP operations in unit tests; use real LDAP in E2E tests

## Code Patterns & Conventions

### Middleware Pattern

All HTTP handlers follow the standard Go middleware signature:

```go
func MiddlewareName(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Pre-processing logic here

        // Call next handler
        next.ServeHTTP(w, r)

        // Post-processing logic here (if needed)
    })
}
```

**Important:** Middleware should fail fast and return errors immediately rather than calling `next.ServeHTTP()` if validation fails.

### Context Keys

**Current context keys** (defined in `internal/handlers/types.go`):
- Context keys exist for passing tenant config and user data between middleware

**CRITICAL GUIDELINE:**
- **Avoid adding new context keys**
- Prefer alternative approaches for passing data:
  - Function parameters
  - Struct fields
  - Closure variables
  - Return values
- Only use context for request-scoped data that truly needs to cross API boundaries

### Error Handling

Return HTTP error responses with appropriate status codes:

- **400 Bad Request**: Malformed request, missing required headers
- **401 Unauthorized**: Authentication failed (invalid credentials)
- **403 Forbidden**: Authorized but not authorized (e.g., no groups)
- **404 Not Found**: Tenant configuration not found
- **500 Internal Server Error**: Server-side errors (LDAP connection failures, token signing errors)

**Pattern:**
```go
http.Error(w, "Error message", http.StatusCode)
return
```

### LDAP Operations

Use the `LDAPAuthenticator` interface (defined in `internal/ldap/tenant-authenticator.go`):

```go
type LDAPAuthenticator interface {
    // AuthN performs LDAP Bind to validate username/password
    AuthN(username, password string) (*user.User, error)

    // AuthZ fetches groups for an authenticated user
    AuthZ(user *user.User) (*user.User, error)
}
```

**Key points:**
- `AuthN()` = Authentication via LDAP Bind
- `AuthZ()` = Authorization via LDAP Search for groups
- Use parameterized LDAP queries to prevent injection attacks
- LDAP queries use paging for large result sets (see `LDAP_PAGE_SIZE`)

### Prometheus Metrics

Follow the existing metrics pattern (see `*_metrics.go` files):

**Metric types:**
- **Counter**: Monotonically increasing values (e.g., total auth attempts)
- **Histogram**: Distribution of values (e.g., request duration)
- **Gauge**: Current value (e.g., active connections)

**Pattern:**
```go
// Define metrics as package-level variables
var authAttemptsTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "ldap_auth_attempts_total",
        Help: "Total number of authentication attempts",
    },
    []string{"status"}, // Labels
)

// Register metrics in init()
func init() {
    prometheus.MustRegister(authAttemptsTotal)
}

// Increment metrics in code
authAttemptsTotal.WithLabelValues("success").Inc()
```

### Configuration

**Environment Variables** (loaded in code):
- LDAP connection settings: `LDAP_SERVER`, `LDAP_PORT`, `LDAP_BINDDN`, `LDAP_PASSWD`
- LDAP behavior: `LDAP_USE_SSL`, `LDAP_START_TLS`, `LDAP_SKIP_TLS_VERIFICATION`, `LDAP_PAGE_SIZE`
- JWT settings: `JWT_ISSUER_FQDN`, `TOKEN_LIFETIME`

**Tenant Configuration Files** (JSON files in `/etc/ldap-jwt-generator/ldap-configs/`):
- File name = Tenant ID (e.g., `tenant1.json`)
- Contains: `userBase`, `userFilter`, `groupSources[]`
- Loaded by TenantRegistry on startup

**Signing Keys** (ECDSA-P512 key pair):
- Private key: `/etc/ldap-jwt-generator/signing-keys/ecdsa-private-key.pem`
- Public key: `/etc/ldap-jwt-generator/signing-keys/ecdsa-public-key.pem`

### Testing Conventions

**Use standard Go testing package:**
- Import `testing` package (NOT Ginkgo/Gomega)
- Write simple, straightforward tests
- Use table-driven tests where appropriate

**Example table-driven test:**
```go
func TestSomething(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid input", "test", "result", false},
        {"invalid input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := FunctionUnderTest(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
            }
            if result != tt.expected {
                t.Errorf("expected: %v, got: %v", tt.expected, result)
            }
        })
    }
}
```

## Testing with Mise

### Test Skill Usage

When the user asks to "run tests" or "test this", execute:
```bash
mise task run test:all
```

This runs the complete test suite in order:
1. **Linting** (`test:lint`): `go fmt`, `go vet`, `golangci-lint run`
2. **Unit tests** (`test:unit`): Fast, isolated tests with coverage and race detection
3. **E2E tests** (`test:e2e`): Integration tests with real LDAP server

### Test Breakdown

#### 1. Linting (`mise task run test:lint`)
- `go fmt ./...` - Format code according to Go standards
- `go vet ./...` - Static analysis for common errors
- `golangci-lint run ./...` - Comprehensive linting (imports, complexity, etc.)

#### 2. Unit Tests (`mise task run test:unit`)
```bash
go test -v -cover -race ./...
```
- `-v`: Verbose output
- `-cover`: Code coverage analysis
- `-race`: Race condition detection

**What gets tested:**
- Individual functions and methods
- Error handling paths
- Edge cases and boundary conditions
- No external dependencies (mocked LDAP)

#### 3. E2E Tests (`mise task run test:e2e`)

**Automatic setup:**
1. Depends on `dev:ldap:start` - spins up OpenLDAP container
2. Depends on `dev:api:start` - builds and starts API container
3. Runs `go test -v ./test/e2e/token_e2e_test.go`
4. Post-depends on `dev:api:stop` and `dev:ldap:stop` - cleanup

**E2E test environment:**
- **Docker network**: `ldap-jwt-test`
- **OpenLDAP container**: `ldap-jwt-test-ldap`
  - Image: `osixia/openldap:1.5.0`
  - Domain: `example.org`
  - Admin password: `admin`
  - Port: `389` (exposed to localhost)
  - Test data loaded from `test/fixtures/ldif/test-data.ldif`
- **API container**: `ldap-jwt-test-api`
  - Built from local codebase
  - Port: `8080` (exposed to localhost)
  - Mounted tenant configs from `test/fixtures/tenant-configs/`
  - Mounted signing keys from `test/fixtures/signing-keys/`

**What E2E tests validate:**
- Real LDAP authentication flows (Bind operations)
- Real LDAP group searches (Search operations)
- JWT token generation and structure
- HTTP response codes and bodies
- End-to-end request/response cycle

### Debugging Tests

**Manual LDAP server management:**
```bash
# Start LDAP server
mise task run dev:ldap:start

# Start API server
mise task run dev:api:start

# View logs
mise task run dev:logs

# Query LDAP directly
docker exec -it ldap-jwt-test-ldap ldapsearch \
  -x -D "cn=admin,dc=example,dc=org" -w admin \
  -b "dc=example,dc=org" "(objectClass=*)"

# Test API manually
curl -X GET http://localhost:8080/token \
  -H "Authorization: Basic $(echo -n 'admin-kube1:password' | base64)" \
  -H "Tenant-Id: tenant1"

# Stop services
mise task run dev:api:stop
mise task run dev:ldap:stop
```

**Common debugging scenarios:**
- **LDAP connection fails**: Check `dev:logs` for LDAP startup errors
- **Authentication fails**: Verify test data loaded with ldapsearch
- **JWT signing fails**: Check signing keys exist in `test/fixtures/signing-keys/`
- **Test timeouts**: LDAP server may need more startup time (increase sleep in mise.toml)

## Important Notes for Claude Code

### Critical: Request User Approval First

**When modifying E2E tests:**
- **STOP and request user approval FIRST**
- E2E tests validate critical authentication flows
- Changes may affect production behavior assumptions
- User needs to review and approve test changes

**When changing JWT claims:**
- **STOP and request user approval FIRST**
- JWT claims structure affects all token consumers
- Breaking changes impact downstream systems
- This is a critical contract that requires user sign-off

### Modification Guidelines

**When modifying auth logic:**
- Always update unit tests
- Ask user before modifying E2E tests
- Test both success and failure paths

**When adding new tenant config fields:**
- Update types in `internal/ldap/types.go`
- Update test fixtures in `test/fixtures/tenant-configs/`
- Document new fields in README.md

**When adding metrics:**
- Follow existing pattern in `*_metrics.go` files
- Use appropriate metric type (counter/histogram/gauge)
- Register metrics in `init()`
- Document in README.md under Prometheus Metrics section

**Context usage:**
- Avoid adding new context keys
- Prefer alternative approaches for passing data
- Function parameters, struct fields, return values

### Security Considerations

**Never log sensitive data:**
- ❌ Don't log passwords, tokens, or credentials
- ❌ Don't log full LDAP bind DNs in error messages
- ✅ Log usernames, tenant IDs, operation outcomes

**Input validation:**
- Validate all user input from HTTP headers
- Sanitize data before passing to LDAP queries
- Use parameterized LDAP queries (placeholders like `%s`)
- Never concatenate user input directly into LDAP filters

**LDAP injection prevention:**
- Use `ldap.EscapeFilter()` for user-supplied filter values
- The existing code uses parameterized queries (`%s` placeholders)
- Never construct LDAP filters with string concatenation

**Example secure LDAP query:**
```go
// GOOD: Parameterized query
filter := fmt.Sprintf("(cn=%s)", username)
// The ldap library handles escaping

// BAD: String concatenation (DO NOT DO THIS)
filter := "(cn=" + username + ")"
```

### Performance Considerations

**LDAP caching:**
- LDAP queries are NOT cached (each request hits LDAP)
- Token lifetime determines how often users re-authenticate
- Longer token lifetime = fewer LDAP queries
- Default: 4 hours

**LDAP paging:**
- Large group searches use LDAP paging (default page size: 1000)
- Controlled by `LDAP_PAGE_SIZE` environment variable
- Prevents memory issues with large result sets

**Avoid unnecessary LDAP roundtrips:**
- Don't make multiple LDAP queries if one will suffice
- Cache results within a single request if needed (request-scoped cache)
- Use appropriate LDAP filters to minimize result set size

### Code Quality Standards

**Before committing:**
1. Run `mise task run test:all` - all tests must pass
2. Code must be formatted (`go fmt`)
3. No linting errors (`golangci-lint`)
4. No race conditions (`go test -race`)

**Code style:**
- Follow Go best practices and idioms
- Keep functions small and focused (single responsibility)
- Use meaningful variable names
- Add comments for non-obvious logic
- Document exported functions and types

**Error messages:**
- Be specific and actionable
- Include context (what operation failed, why)
- Don't expose internal implementation details to users
- Use consistent error message format

## Project Metadata

**Repository:** https://github.com/ca-gip/ldap-jwt-generator
**License:** See [LICENSE](./LICENSE) file
**Related Projects:** [Kubi](https://github.com/ca-gip/kubi) - Kubernetes User Management
**Documentation:** See [README.md](./README.md) for user-facing docs

---

**Last Updated:** 2026-02-26
**Maintained By:** Project maintainers (see git commit history)
