package handlers

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var Histogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "kubi_http_requests",
	Help:    "Time per requests",
	Buckets: []float64{1, 2, 5, 6, 10}, //defining small buckets as this app should not take more than 1 sec to respond
}, []string{"path"}) // this will be partitioned by the HTTP path

func Prometheus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use URL path directly (no gorilla/mux CurrentRoute)
		path := r.URL.Path

		timer := prometheus.NewTimer(Histogram.WithLabelValues(path))
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}
