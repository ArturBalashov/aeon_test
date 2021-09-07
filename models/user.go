package models

import (
	"context"
)

type User struct {
	ID           uint    `json:"id"`
	Login        string  `json:"login"`
	Password     string  `json:"password"`
	PasswordSalt string  `json:"-"`
	Balance      float32 `json:"balance"`
}

type Payment struct {
	ID              uint
	UserID          uint
	Amount          float32
	PreviousBalance float32
	Balance         float32
}

type JWT struct {
	ID     uint   `json:"id"`
	UserID uint   `json:"user_id"`
	Token  string `json:"token"`
}


type UserContext struct {
	Token string
}

func NewUserContext(ctx context.Context) UserContext {
	if ctx == nil || ctx.Value("user_info") == nil {
		return UserContext{}
	}

	return ctx.Value("user_info").(UserContext)
}