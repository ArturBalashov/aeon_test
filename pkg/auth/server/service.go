package server

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jackc/pgx/v4"
	"github.com/k3nnyM/aeon_test/models"
	"github.com/k3nnyM/aeon_test/pkg/auth/service"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/k3nnyM/aeon_test/pkg/auth/config"
)

const signKey = "321fss"

type Token struct {
	jwt.StandardClaims

	UserID uint
}

func NewService(db *pgxpool.Pool, logger *zap.Logger, cfg *config.Config) *serviceImplementation {
	return &serviceImplementation{
		db:     db,
		logger: logger,
		cfg:    cfg,
	}
}

type serviceImplementation struct {
	db     *pgxpool.Pool
	logger *zap.Logger
	cfg    *config.Config
}

func (s *serviceImplementation) Login(w http.ResponseWriter, r *http.Request) {
	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeResponse(w, err.Error())
		return
	}

	if req.Login == "" || req.Password == "" {
		s.writeResponse(w, fmt.Sprintf("wrong login: %s or password: %s", req.Login, req.Password))
		return
	}

	var user models.User
	if err := s.db.QueryRow(context.Background(),
		"SELECT id, login, password, password_salt FROM users WHERE login = $1",
		req.Login,
	).Scan(&user.ID, &user.Login, &user.Password, &user.PasswordSalt); err != nil {
		s.logger.Warn("can't select user", zap.Error(err))
		s.writeResponse(w, "user not found")
		return
	}

	hash := sha512.New()
	hash.Write([]byte(user.Password))

	userPassword := fmt.Sprintf("%x", hash.Sum([]byte(user.PasswordSalt)))
	if userPassword != req.Password {
		s.writeResponse(w, "wrong password")
		return
	}

	expiresAt := time.Now().Add(time.Duration(1440)*time.Minute).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &Token{
		jwt.StandardClaims{
			ExpiresAt: expiresAt,
			IssuedAt:  time.Now().Unix(),
		},
		user.ID,
	})
	generatedToken, err := token.SignedString([]byte(signKey))
	if err != nil {
		s.logger.Error("can't signed token", zap.Error(err))
		s.writeResponse(w, "can't create token")
		return
	}

	jwtToken := models.JWT{Token: generatedToken}
	var id int
	if err := s.db.QueryRow(context.Background(),
		"INSERT INTO jwts(user_id, token) VALUES($1, $2) RETURNING id",
		user.ID, jwtToken.Token,
	).Scan(&id); err != nil {
		s.logger.Warn("can't get token from db", zap.Error(err))
		s.writeResponse(w, "no token")
		return
	}

	s.writeResponse(w, jwtToken.Token)
}

func (s *serviceImplementation) Logout(w http.ResponseWriter, r *http.Request) {
	var req service.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeResponse(w, err.Error())
		return
	}

	if req.Token == "" {
		s.writeResponse(w, "no token")
		return
	}

	if _, err := s.db.Exec(context.Background(), "DELETE FROM jwts WHERE token = $1", req.Token); err != nil {
		s.logger.Error("can't delete token from db", zap.Error(err))
		s.writeResponse(w, "can't logout")
		return
	}
	s.writeResponse(w, "logout success")
}

func (s *serviceImplementation) Payment(w http.ResponseWriter, r *http.Request) {
	t, hasToken := GetAuthorizationHeader(r)
	if !hasToken {
		s.writeResponse(w, "no token")
		return
	}

	token, err := ParseToken(t, signKey)
	if err != nil {
		s.writeResponse(w, err.Error())
		return
	}
	tx, err := s.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		s.logger.Error("can't begin tx", zap.Error(err))
		s.writeResponse(w, "internal error")
		return
	}
	defer func(){
		s.logger.Error("error tx", zap.Error(tx.Rollback(context.Background())))
	}()
	var userBalance float32
	if err := tx.QueryRow(context.Background(),
		"SELECT balance FROM users WHERE id = $1",
		token.UserID,
	).Scan(&userBalance); err != nil {
		s.logger.Error("can't get a balance from db", zap.Error(err))
		s.writeResponse(w, "internal error")
		return
	}

	if userBalance < 1.1 {
		s.writeResponse(w, "not enough balance")
		return
	}
	oldBalance := userBalance
	userBalance -= 1.1
	if _, err := tx.Exec(context.Background(), "UPDATE users SET balance = $1", userBalance); err != nil {
		s.logger.Error("can't update balance", zap.Error(err))
		s.writeResponse(w, "internal error")
		return
	}
	if err := tx.QueryRow(context.Background(),
		"INSERT INTO payments(user_id, amount, previous_balance, balance) VALUES ($1, $2, $3, $4)",
		token.UserID, 1.1, oldBalance, userBalance,
	).Scan(); err != nil {
		s.logger.Error("can't insert payment info", zap.Error(err))
		s.writeResponse(w, "internal error")
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		s.logger.Error("can't commit tx", zap.Error(err))
		s.writeResponse(w, "internal error")
		return
	}

	s.writeResponse(w, "success")
}


func (s *serviceImplementation) parseToken(t string) *Token {
	jwtFromBase, err := s.GetTokenFromDB(context.WithValue(context.Background(), "user_info", models.UserContext{
		Token: t,
	}))
	if err != nil {
		s.logger.Error("can't get jwt from db", zap.Error(err), zap.String("token", t))
		return nil
	}

	if jwtFromBase != t {
		s.logger.Warn("token from db not equal token from request", zap.String("request token", t))
		return nil
	}

	userToken, err := ParseToken(t, signKey)
	if err != nil {
		s.logger.Error("wrong token", zap.Error(err))
		return nil
	}

	return userToken
}




func (s *serviceImplementation) GetTokenFromDB(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Value("user_info") == nil {
		s.logger.Warn("error context", zap.String("context", fmt.Sprintf("%v", ctx)))
		return "", errors.New("wrong context")
	}

	var jwtToken models.JWT
	if err := s.db.QueryRow(context.Background(),
		"SELECT id, user_id, token FROM jwts WHERE token = $1",
		ctx.Value("user_info").(models.UserContext).Token,
	).Scan(&jwtToken.ID, &jwtToken.UserID, &jwtToken.Token); err != nil {
		s.logger.Warn("no token from db", zap.Error(err))
		return "", err
	}
	if jwtToken.Token == "" {
		s.logger.Warn("can't find token from db", zap.String("token", ctx.Value("user_info").(models.UserContext).Token))
		return "", errors.New("wrong token")
	}

	return jwtToken.Token, nil
}



func ParseToken(t, signingKey string) (*Token, error) {
	userToken := &Token{}

	token, err := jwt.ParseWithClaims(t, userToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(signingKey), nil
	})
	if err != nil {
		fmt.Println("ERRT", err)
		return nil, errors.New("wrong token")
	}

	if !token.Valid {
		fmt.Println("ERRT000", token)
		return nil, errors.New("wrong token")
	}

	return userToken, nil
}

func GetAuthorizationHeader(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 {
		return "", false
	}

	if strings.Trim(headerParts[0], ": ") != "Bearer" {
		return "", false
	}

	return headerParts[1], true
}

func (s *serviceImplementation) writeResponse(w http.ResponseWriter, response string) {
	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.Error("Send success response failed", zap.Error(err))
	}
}