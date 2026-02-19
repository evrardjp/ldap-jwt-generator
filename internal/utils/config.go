package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/rest"
	podSecurity "k8s.io/pod-security-admission/api"
)

var Config *types.Config

// Convenience function to default to a fallback string if the env var is not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Build and validates the configuration from the environment variables
// Todo: Split the makeconfig in two: One for the api+webhook, one for the operator.
func MakeConfig() (*types.Config, error) {

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve system cert pool, exiting for security reason")
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if ok := rootCAs.AppendCertsFromPEM(kubeCA); !ok {
		return nil, fmt.Errorf("cannot add Kubernetes CA, exiting for security reason")
	}

	return &types.Config{
		Tenant:                          tenant,
		PodSecurityAdmissionEnforcement: podSecurityAdmissionEnforcement,
		PodSecurityAdmissionWarning:     podSecurityAdmissionWarning,
		PodSecurityAdmissionAudit:       podSecurityAdmissionAudit,

		KubeCa:             caEncoded,
		KubeCaText:         string(kubeCA),
		KubeToken:          string(kubeToken),
		PublicApiServerURL: publicApiServerURL,
		ApiServerTLSConfig: tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            rootCAs,
		},
		TokenLifeTime:           getEnv("TOKEN_LIFETIME", "4h"),
		ExtraTokenLifeTime:      getEnv("EXTRA_TOKEN_LIFETIME", "720h"),
		Locator:                 getEnv("LOCATOR", KubiLocatorIntranet),
		NetworkPolicy:           networkpolicyEnabled,
		CustomLabels:            customLabels,
		DefaultPermission:       getEnv("DEFAULT_PERMISSION", ""),
		PrivilegedNamespaces:    strings.Split(getEnv("PRIVILEGED_NAMESPACES", ""), ","),
		Blacklist:               strings.Split(getEnv("BLACKLIST", ""), ","),
		Whitelist:               whitelist,
		BlackWhitelistNamespace: getEnv("BLACK_WHITELIST_NAMESPACE", "default"),
	}, nil
}

// Parse CustomLabels from a string to a map holding the key value
func parseCustomLabels(rawLabels string) (labels map[string]string) {
	labelsPattern := regexp.MustCompile(`(?P<key>\w+)=(?P<value>[^,]+)`)

	if !labelsPattern.MatchString(rawLabels) {
		return map[string]string{}
	}

	matches := labelsPattern.FindAllStringSubmatch(rawLabels, -1)
	labels = make(map[string]string, len(matches))
	for _, match := range matches {
		if !(match[1] == "creator" || match[1] == "customer") {
			labels[match[1]] = match[2]
		}
	}

	return
}

// Modifier that Fix too old resource version issues
var DefaultWatchOptionModifier = func(options *v1.ListOptions) {
	options.ResourceVersion = ""
	options.FieldSelector = fields.Everything().String()
}
