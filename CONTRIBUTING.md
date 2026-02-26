# Developer guide

This guide helps you get started developing ldap-jwt-generator

## Prerequisites

Make sure you have the following dependencies installed before setting up your developer environment:

 - Git
 - Docker
 - mise
 - curl
 - (optional) openSSL

## Test instructions

```
mise task run test:all 
```

This will run all tests:

- Linting
- unit tests
- e2e

## Contributing to ldap-jwt-generator

Whenever you want to contribute, always start by creating a test case.

When you're done with your code change, run the test instructions to see if everything still works.

## Releasing

### Tag and push

git tag v1.0.0
git push origin v1.0.0

### Create GitHub release

gh release create v1.0.0 --title "v1.0.0" --notes "Release notes here"

The container image will be automatically built and pushed to:

- ghcr.io/<owner>/ldap-jwt-generator:v1.0.0
- ghcr.io/<owner>/ldap-jwt-generator:1.0
- ghcr.io/<owner>/ldap-jwt-generator:1
- ghcr.io/<owner>/ldap-jwt-generator:latest

### Verifying SBOM and Provenance

#### View SBOM

  docker buildx imagetools inspect ghcr.io/<owner>/ldap-jwt-generator:v1.0.0 --format "{{ json .SBOM }}"

#### View provenance

  docker buildx imagetools inspect ghcr.io/<owner>/ldap-jwt-generator:v1.0.0 --format "{{ json .Provenance }}"

#### Using cosign to verify attestations

  cosign verify-attestation ghcr.io/<owner>/ldap-jwt-generator:v1.0.0 \
    --type slsaprovenance \
    --certificate-identity-regexp="^https://github.com/" \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
