# LDAP-JWT-Generator

> A lightweight, multi-tenant LDAP authentication service that generates JWT tokens for users authenticated via LDAP.

## Overview

`ldap-jwt-generator` is a Go-based authentication microservice that bridges LDAP directory services with JWT-based authentication systems. It validates user credentials against LDAP, retrieves user group memberships, and issues signed JWT tokens containing user identity and authorization claims.

This service is part of the [Kubi project ecosystem](https://github.com/ca-gip/kubi) and is designed for Kubernetes-native deployments where LDAP authentication needs to be exposed via standardized JWT tokens.

## Features

- **Multi-tenant LDAP Support**: Configure different LDAP search parameters for multiple tenants
- **JWT Token Generation**: Issue JWT tokens signed with ECDSA-P512 algorithm
- **Group-based Authorization**: Fetch and validate user group memberships from LDAP
- **Prometheus Metrics**: Export authentication and LDAP operation metrics
- **Kubernetes Integration**: Native support for Kubernetes deployments with ConfigMaps and Secrets
- **Secure by Default**: TLS support, credential validation, and secure token signing

## Architecture

The service implements an HTTP middleware chain that processes authentication requests:

```
┌─────────────────────────────────────────────────────────────────┐
│  HTTP Request                                                   │
│  Authorization: Basic <credentials>                             │
│  Tenant-Id: <tenant>                                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  WithTenantConfig    │ ← Load tenant LDAP config
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  WithBasicAuth       │ ← Validate credentials (LDAP Bind)
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  WithGroupEnrichment │ ← Fetch user groups (LDAP Search)
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  GenerateJWT         │ ← Create signed JWT token
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  HTTP 201 Response   │
              │  Body: JWT Token     │
              └──────────────────────┘
```

## Prerequisites

- **Go**: 1.26 or later
- **Docker**: For building and testing
- **mise**: Task automation tool ([installation guide](https://mise.jdx.dev/getting-started.html))
- **LDAP Server**: OpenLDAP, Active Directory, or compatible LDAP service
- **curl**: For testing API requests

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/ca-gip/ldap-jwt-generator.git
cd ldap-jwt-generator

# Install dependencies (mise will install Go and golangci-lint)
mise install

# Build the binary and Docker image
mise task run build
```

### Docker Image

```bash
docker pull ghcr.io/ca-gip/ldap-jwt-generator:latest
```

## Configuration

### Environment Variables

The service requires the following environment variables:

| Variable | Description | Example | Required | Default |
|----------|-------------|---------|----------|---------|
| `LDAP_SERVER` | LDAP server hostname or IP | `ldap.example.com` | Yes | - |
| `LDAP_PORT` | LDAP server port | `389` | No | `389` |
| `LDAP_BINDDN` | Service account DN for LDAP binds | `cn=admin,dc=example,dc=org` | Yes | - |
| `LDAP_PASSWD` | Service account password | `secretpassword` | Yes | - |
| `LDAP_USE_SSL` | Enable SSL connection | `true` | No | `false` |
| `LDAP_START_TLS` | Enable StartTLS (use with port 389) | `true` | No | `false` |
| `LDAP_SKIP_TLS_VERIFICATION` | Skip TLS certificate verification | `true` | No | `true` |
| `LDAP_PAGE_SIZE` | LDAP paging size for searches | `1000` | No | `1000` |
| `JWT_ISSUER_FQDN` | JWT issuer FQDN for token claims | `auth.example.com` | Yes | - |
| `TOKEN_LIFETIME` | JWT token expiration duration | `4h` | No | `4h` |

### Tenant Configuration Files

Each tenant requires a JSON configuration file that defines LDAP search parameters. These files should be mounted at `/etc/ldap-jwt-generator/ldap-configs/`.

**File naming convention:** `<tenant-id>.json`

**Example configuration** (`tenant1.json`):

```json
{
  "userBase": "ou=Users,dc=example,dc=org",
  "userFilter": "(cn=%s)",
  "groupSources": [
    {
      "base": "ou=Groups,dc=example,dc=org",
      "filter": "(&(objectClass=groupOfNames)(member=%s))"
    }
  ]
}
```

**Configuration fields:**

- `userBase`: Base DN for user searches
- `userFilter`: LDAP filter for finding users (use `%s` as username placeholder)
- `groupSources`: Array of group search configurations
  - `base`: Base DN for group searches
  - `filter`: LDAP filter for finding groups (use `%s` as user DN placeholder)

### Signing Keys

Generate ECDSA-P512 key pair for JWT signing:

```bash
# Generate private key
openssl ecparam -genkey -name secp521r1 -noout -out ecdsa-private-key.pem

# Generate public key
openssl ec -in ecdsa-private-key.pem -pubout -out ecdsa-public-key.pem
```

Mount these keys at `/etc/ldap-jwt-generator/signing-keys/`:
- `ecdsa-private-key.pem` - Private key for signing tokens
- `ecdsa-public-key.pem` - Public key for token verification

## Usage

### API Endpoint

**Endpoint:** `GET /token`

**Request Headers:**
- `Authorization: Basic <base64(username:password)>` - User credentials
- `Tenant-Id: <tenant-id>` - Tenant identifier matching configuration file name

**Example Request:**

```bash
# Authenticate as user "admin-kube1" with tenant "tenant1"
curl -X GET http://localhost:8080/token \
  -H "Authorization: Basic $(echo -n 'admin-kube1:password123' | base64)" \
  -H "Tenant-Id: tenant1"
```

**Success Response:**

```
HTTP/1.1 201 Created
Content-Type: text/plain

eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ta3ViZTEiLCJjb250YWN0IjoiYWRtaW5AZXhhbXBsZS5jb20iLCJ1c2VyRE4iOiJjbj1hZG1pbi1rdWJlMSxvdT1Vc2VycyxkYz1leGFtcGxlLGRjPW9yZyIsInRlbmFudCI6InRlbmFudDEiLCJncm91cHMiOlsia3ViZS1hZG1pbnMiXSwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsInN1YiI6ImFkbWluLWt1YmUxIiwiYXVkIjpbImF1dGguZXhhbXBsZS5jb20iXSwiZXhwIjoxNzQwMDAwMDAwLCJuYmYiOjE3Mzk5ODU2MDAsImlhdCI6MTczOTk4NTYwMCwianRpIjoiMTIzNDU2NzgtYWJjZC0xMjM0LWFiY2QtMTIzNDU2Nzg5YWJjIn0.signature
```

**Error Responses:**

- `400 Bad Request` - Missing Tenant-Id header or invalid request
- `401 Unauthorized` - Invalid credentials or authentication failed
- `403 Forbidden` - User does not belong to any groups
- `404 Not Found` - Tenant configuration not found
- `500 Internal Server Error` - Server-side error

### JWT Token Claims

The issued JWT token contains the following claims:

**Custom Claims:**
- `user` - Username (e.g., "admin-kube1")
- `contact` - User email address
- `userDN` - LDAP Distinguished Name
- `tenant` - Tenant identifier
- `groups` - Array of group names user belongs to

**Standard JWT Claims:**
- `iss` - Issuer (from `JWT_ISSUER_FQDN`)
- `sub` - Subject (username)
- `aud` - Audience (array with issuer FQDN)
- `exp` - Expiration time
- `nbf` - Not before time
- `iat` - Issued at time
- `jti` - JWT ID (unique identifier)

**Example decoded token:**

```json
{
  "user": "admin-kube1",
  "contact": "admin@example.com",
  "userDN": "cn=admin-kube1,ou=Users,dc=example,dc=org",
  "tenant": "tenant1",
  "groups": ["kube-admins", "developers"],
  "iss": "auth.example.com",
  "sub": "admin-kube1",
  "aud": ["auth.example.com"],
  "exp": 1740000000,
  "nbf": 1739985600,
  "iat": 1739985600,
  "jti": "12345678-abcd-1234-abcd-123456789abc"
}
```

### Prometheus Metrics

**Endpoint:** `GET /metrics`

Exports the following metrics:
- LDAP authentication attempts (success/failure)
- LDAP query latencies
- JWT token generation counts
- HTTP request durations

## Development

### Quick Start

```bash
# Run all tests (linting, unit, e2e)
mise task run test:all

# Build the project
mise task run build

# Start local LDAP server for development
mise task run dev:ldap:start

# Start local API server
mise task run dev:api:start

# View logs
mise task run dev:logs

# Stop services
mise task run dev:api:stop
mise task run dev:ldap:stop
```

### Available Mise Tasks

| Task | Description |
|------|-------------|
| `build` | Build binary and Docker image |
| `test:lint` | Run code linters (fmt, vet, golangci-lint) |
| `test:unit` | Run unit tests with coverage |
| `test:e2e` | Run end-to-end tests with LDAP containers |
| `test:all` | Run all tests (lint + unit + e2e) |
| `dev:ldap:start` | Start OpenLDAP development server |
| `dev:ldap:stop` | Stop OpenLDAP server |
| `dev:api:start` | Start API server for local testing |
| `dev:api:stop` | Stop API server |
| `dev:logs` | View container logs |
| `clean` | Remove build artifacts |
| `tag:git` | Tag git repository |

For detailed contribution guidelines, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Deployment

### Docker

```bash
docker run -d \
  --name ldap-jwt-generator \
  -p 8080:8080 \
  -e LDAP_SERVER="ldap.example.com" \
  -e LDAP_PORT="389" \
  -e LDAP_BINDDN="cn=admin,dc=example,dc=org" \
  -e LDAP_PASSWD="secretpassword" \
  -e JWT_ISSUER_FQDN="auth.example.com" \
  -e TOKEN_LIFETIME="4h" \
  -v /path/to/tenant-configs:/etc/ldap-jwt-generator/ldap-configs:ro \
  -v /path/to/signing-keys:/etc/ldap-jwt-generator/signing-keys:ro \
  ghcr.io/ca-gip/ldap-jwt-generator:latest
```

### Kubernetes

The service includes Kubernetes deployment manifests in the `deployments/` directory.

**Required resources:**
- **ConfigMap**: Mount tenant configuration JSON files
- **Secret**: Mount ECDSA signing keys
- **Deployment**: Application pods
- **Service**: Internal service endpoint
- **ServiceMonitor**: Prometheus metrics scraping (optional)

**Example ConfigMap:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-jwt-tenant-configs
data:
  tenant1.json: |
    {
      "userBase": "ou=Users,dc=example,dc=org",
      "userFilter": "(cn=%s)",
      "groupSources": [
        {
          "base": "ou=Groups,dc=example,dc=org",
          "filter": "(&(objectClass=groupOfNames)(member=%s))"
        }
      ]
    }
```

**Example Secret:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-jwt-signing-keys
type: Opaque
data:
  ecdsa-private-key.pem: <base64-encoded-private-key>
  ecdsa-public-key.pem: <base64-encoded-public-key>
```

Refer to the `deployments/` directory for complete examples.

## Testing

The project uses a comprehensive testing strategy:

- **Unit Tests**: Fast, isolated tests for individual components
- **E2E Tests**: Full integration tests with real LDAP server
- **Test Fixtures**: Pre-configured LDAP data and tenant configurations

Run tests with:

```bash
# All tests (recommended before committing)
mise task run test:all

# Individual test suites
mise task run test:lint    # Code quality checks
mise task run test:unit    # Unit tests only
mise task run test:e2e     # Integration tests only
```

The E2E test suite automatically:
1. Spins up an OpenLDAP container
2. Loads test data from `test/fixtures/ldif/test-data.ldif`
3. Builds and deploys the API container
4. Runs authentication flow tests
5. Tears down all test infrastructure

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines.

**Before submitting a PR:**
1. Write tests for your changes
2. Run `mise task run test:all` to ensure all tests pass
3. Follow the existing code patterns and conventions

## License

This project is licensed under the terms specified in the [LICENSE](./LICENSE) file.

## Related Projects

- [Kubi](https://github.com/ca-gip/kubi) - Kubernetes User Management
