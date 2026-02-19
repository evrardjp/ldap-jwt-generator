package jwt

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	TokenCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kubi_valid_token_total",
		Help: "Total number of tokens issued",
	}, []string{"status"})

	KubiTokenSizeHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kubi_token_size",
		Help:    "size of a kubi ldap token in bytes",
		Buckets: []float64{512, 1024, 4096, 16384, 65536},
	})
)
