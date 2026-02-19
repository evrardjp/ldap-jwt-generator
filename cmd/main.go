package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"ldap-jwt-generator/internal/handlers"
	"ldap-jwt-generator/internal/jwt"
	"ldap-jwt-generator/internal/ldap"
	"log/slog"
	"net/http"
	"os"
)

const (
	listeningPort = 8080
)

func main() {

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	ldapBaseConfig, errBaseConfig := ldap.NewLDAPBaseConfig()
	if errBaseConfig != nil {
		slog.Error("cannot initialize api: %v", "error", errBaseConfig)
		os.Exit(1)
	}

	ldapTenantConfig, errTenant := ldap.NewLDAPTenantConfig()
	if errTenant != nil {
		slog.Error("cannot initialize api: %v", "error", errTenant)
		os.Exit(1)
	}

	ldapClient := ldap.NewLDAPClient(ldapBaseConfig, ldapTenantConfig)

	tokenIssuer, errTokenIssuer := jwt.NewTokenIssuer()
	if errTokenIssuer != nil {
		slog.Error("unable to create token issuer", "error", errTokenIssuer)
		os.Exit(1)
	}

	router := mux.NewRouter()
	router.Use(handlers.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		slog.Info("endpoint not routed", "method", req.Method, "url", req.URL.String())
	})

	// TODO
	router.HandleFunc("/token", handlers.WithBasicAuth(ldapClient, tokenIssuer.GenerateJWT)).Methods(http.MethodGet)
	router.Handle("/metrics", promhttp.Handler())

	slog.Info("starting server", "port", listeningPort)
	if errListen := http.ListenAndServe(fmt.Sprintf(":%s", listeningPort), router); errListen != nil {
		slog.Error("server failed to start", "error", errListen)
		os.Exit(2)
	}
}
