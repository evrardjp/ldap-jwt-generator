package ldap

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
)

type BaseConfig struct {
	Host            string
	Port            int
	PageSize        uint32
	UseSSL          bool
	StartTLS        bool
	TLSVerification bool
	BindDN          string
	BindPassword    string
	Attributes      []string
}

type GroupSource struct {
	Base   string `json:"base"`
	Filter string `json:"filter"`
}

type TenantConfig struct {
	UserBase     string        `json:"userBase"`
	UserFilter   string        `json:"userFilter"`
	GroupSources []GroupSource `json:"groupSources"`
}

// Validate checks if the tenant configuration has all required fields
func (tc *TenantConfig) Validate() error {
	if tc.UserBase == "" {
		return fmt.Errorf("userBase is required")
	}
	if tc.UserFilter == "" {
		return fmt.Errorf("userFilter is required")
	}
	if len(tc.GroupSources) == 0 {
		return fmt.Errorf("groupSources is required and must have at least one entry")
	}
	for i, gs := range tc.GroupSources {
		if gs.Base == "" {
			return fmt.Errorf("groupSources[%d].base is required", i)
		}
		if gs.Filter == "" {
			return fmt.Errorf("groupSources[%d].filter is required", i)
		}
	}
	return nil
}

func NewLDAPBaseConfig() (*BaseConfig, error) {
	ldapConfig := &BaseConfig{}

	var insecureLDAP bool
	if env := os.Getenv("INSECURE_LDAP"); env != "" {
		insecure, err := strconv.ParseBool(env)
		if err != nil {
			return nil, fmt.Errorf("invalid INSECURE_LDAP %s: %v", env, err)
		}
		if insecure {
			slog.Warn("INSECURE LDAP CONFIGURATION")
		}
		insecureLDAP = insecure
	}

	ldapServer := os.Getenv("LDAP_SERVER")
	if ldapServer == "" {
		return nil, fmt.Errorf("host is required")
	}
	ldapConfig.Host = ldapServer

	ldapPort := os.Getenv("LDAP_PORT")
	// use ssl -> port 636
	// implicit tls -> connect port 389 in clear text, then startTLS
	// explicit tls -> we probably don't care.
	switch ldapPort {
	case "":
		return nil, fmt.Errorf("LDAP_PORT is empty, set it to port 389 or 636")
	case "389":
		ldapConfig.Port = 389
		if !insecureLDAP {
			ldapConfig.StartTLS = true
			ldapConfig.UseSSL = false
			ldapConfig.TLSVerification = true
		}

	case "636":
		ldapConfig.Port = 636
		if !insecureLDAP {
			ldapConfig.StartTLS = false
			ldapConfig.UseSSL = false
			ldapConfig.TLSVerification = true
		}
	default:
		var err error
		ldapConfig.Port, err = strconv.Atoi(ldapPort)
		if err != nil {
			return nil, fmt.Errorf("invalid LDAP_PORT: %s, %v", ldapPort, err)
		}
	}

	ldapBindDN := os.Getenv("LDAP_BINDDN")
	switch {
	case ldapBindDN == "":
		return nil, fmt.Errorf("LDAP_BINDDN env var is mandatory")
	case len(ldapBindDN) < 2 || len(ldapBindDN) > 200:
		return nil, fmt.Errorf("length for LDAP_BINDDN must be between 2 and 200 characters, got %v", len(ldapBindDN))
	}
	ldapConfig.BindDN = ldapBindDN

	ldapBindPassword := os.Getenv("LDAP_PASSWD")
	switch {
	case ldapBindPassword == "":
		return nil, fmt.Errorf("LDAP_PASSWD env var is mandatory")
	case len(ldapBindPassword) < 2 || len(ldapBindPassword) > 200:
		return nil, fmt.Errorf("length for LDAP_PASSWD must be between 2 and 200 characters, got %v", len(ldapBindPassword))
	}
	ldapConfig.BindPassword = ldapBindPassword

	ldapPageSizeEnv, pageSizeFound := os.LookupEnv("LDAP_PAGE_SIZE")
	if !pageSizeFound {
		ldapPageSizeEnv = "1000"
	}
	ldapPageSize, errLdapPageSize := strconv.ParseUint(ldapPageSizeEnv, 10, 32)
	if errLdapPageSize != nil {
		return nil, fmt.Errorf("invalid LDAP_PAGE_SIZE %s, must be an integer %v", ldapPageSizeEnv, errLdapPageSize)
	}
	ldapConfig.PageSize = uint32(ldapPageSize)
	return ldapConfig, nil
}
