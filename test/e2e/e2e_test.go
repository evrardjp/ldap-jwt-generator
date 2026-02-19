/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//lint:file-ignore U1000 Ignore all unused code, it's generated

package e2e

// NOTE: This e2e test file has been temporarily disabled during the refactoring from kubi to ldap-jwt-generator.
// This test suite tests the entire kubi operator stack (operator, API, authentication webhook, RBAC, etc.)
// which is much larger than the ldap-jwt-generator service we've refactored.
//
// Old architecture tested (kubi operator stack):
// - Kubi operator creating Kubernetes projects, namespaces, service accounts, role bindings, network policies
// - Kubi API generating kubeconfigs
// - Kubi authentication webhook validating JWT tokens
// - Full RBAC integration with Kubernetes
//
// New architecture (ldap-jwt-generator):
// - Simple HTTP service with endpoints:
//   - GET /token - Issue JWT tokens with LDAP authentication
//   - GET /metrics - Prometheus metrics
// - Multi-tenant LDAP support with JSON config files
// - JWT tokens with all security claims (iss, aud, exp, nbf, iat, sub, jti)
//
// TODO: Create new e2e tests for ldap-jwt-generator that test:
// 1. GET /token with valid Tenant-Id and Basic Auth → returns JWT with all claims
// 2. GET /token without Tenant-Id → returns 400 Bad Request
// 3. GET /token with invalid Tenant-Id → returns 400 Bad Request
// 4. GET /token with invalid credentials → returns 401 Unauthorized
// 5. JWT token validation with public key
// 6. JWT claims verification (iss, aud, exp, nbf, iat, sub, jti, username, email, userDN, tenantId, groups)
// 7. GET /metrics returns Prometheus metrics
//
// Original tests relied on:
// - github.com/ca-gip/kubi/internal/services (old kubi package)
// - github.com/ca-gip/kubi/pkg/apis/cagip/v1 (old kubi CRDs)
// - github.com/ca-gip/kubi/pkg/generated/clientset/versioned (old kubi client)
// - github.com/ca-gip/kubi/pkg/types (old kubi types)
// - github.com/ca-gip/kubi/test/utils (old kubi test utils)
// - Full Kubernetes cluster with kubi operator deployed
