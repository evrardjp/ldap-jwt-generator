package ldap

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	LdapGroupsHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kubi_ldap_groups_number",
		Help:    "Number of ldap groups of a user",
		Buckets: []float64{10, 60, 100, 200, 500},
	})

	LdapGroupsRequestDurationHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kubi_ldap_groups_request_duration",
		Help:    "Duration of ldap user's groups requests",
		Buckets: []float64{1, 2, 5, 6, 10},
	})
)
