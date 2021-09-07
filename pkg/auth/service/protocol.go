package service

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}