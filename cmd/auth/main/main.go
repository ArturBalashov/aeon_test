package main

import (
	"context"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/k3nnyM/aeon_test/pkg/auth/server"
	"net/http"
	"os"
	"os/signal"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/k3nnyM/aeon_test/pkg/auth/config"
)

func main() {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		os.Stdout,
		zap.DebugLevel,
	))
	logger.Info("Starting service...")

	cfg, err := config.NewAuthConfig()
	if err != nil {
		logger.Error("config error", zap.Error(err))
		return
	}

	ctx := context.Background()
	db, err := pgxpool.Connect(ctx, cfg.DBConnectionString)
	if err != nil {
		logger.Error("connect to database was failed", zap.Error(err))
		return
	}

	srv := server.NewService(db, logger, cfg)
	handler := server.NewHTTPHandler(srv)

	httpServer := &http.Server{
		Addr:         cfg.HTTPAddr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 20,
		Handler:      handler,
	}

	logger.Info("Service was started, Auth http listening", zap.String("address", cfg.HTTPAddr))
	err = httpServer.ListenAndServe()
	if err != nil {
		logger.Error("listen error", zap.Error(err))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Info("Auth service shutdown")
		return
	}

	logger.Info("Service was stopped")

}