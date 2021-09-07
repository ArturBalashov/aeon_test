package server

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/k3nnyM/aeon_test/pkg/auth/service"
)

func NewHTTPHandler(srv service.Service) http.Handler {
	r := mux.NewRouter().StrictSlash(true).PathPrefix("/auth").Subrouter()

	r.Methods("POST").Path("/login").HandlerFunc(srv.Login)
	r.Methods("POST").Path("/logout").HandlerFunc(srv.Logout)
	r.Methods("POST").Path("/payment").HandlerFunc(srv.Payment)

	return r
}
