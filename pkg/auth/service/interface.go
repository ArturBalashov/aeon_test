package service

import "net/http"

type Service interface {
	Login(http.ResponseWriter, *http.Request)
	Logout(http.ResponseWriter, *http.Request)
	Payment(http.ResponseWriter, *http.Request)
}
