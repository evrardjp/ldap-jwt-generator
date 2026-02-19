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

package e2e

// NOTE: This test suite file has been temporarily disabled during the refactoring from kubi to ldap-jwt-generator.
// This was the Ginkgo test suite setup for the old kubi e2e tests.
//
// The new e2e tests are in token_test.go and use standard Go testing (no Ginkgo framework).
//
// Original tests relied on:
// - github.com/ca-gip/kubi/test/utils (old kubi package)
// - github.com/onsi/ginkgo/v2 (Ginkgo BDD framework)
// - github.com/onsi/gomega (Gomega matchers)
