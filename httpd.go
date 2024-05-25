package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

const (
	HEALTH_CHECK_PORT = 81
)

func startHealthCheckServer() {
	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", HEALTH_CHECK_PORT), nil))
}
