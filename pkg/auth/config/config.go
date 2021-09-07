package config

import (
	"fmt"
	"os"
)

type Config struct {
	HTTPAddr           string
	DBConnectionString string
	DBHost             string
	DBPort             string
	DBUser             string
	DBPass             string
	DBName             string
}

// NewAuthConfig for instantiate config from environment
func NewAuthConfig() (*Config, error) {
	cfg := Config{}

	EnvToString(&cfg.HTTPAddr, "AEON_HTTP_ADDR", "127.0.0.1")
	EnvToString(&cfg.DBConnectionString, "AEON_DB_CONNECTION", "")
	EnvToString(&cfg.DBHost, "AEON_DB_HOST", "localhost")
	EnvToString(&cfg.DBPort, "AEON_DB_PORT", "5432")
	EnvToString(&cfg.DBUser, "AEON_DB_USER", "postgres")
	EnvToString(&cfg.DBPass, "AEON_DB_PASSWORD", "test")
	EnvToString(&cfg.DBName, "AEON_DB_NAME", "test")

	cfg.DBConnectionString = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", cfg.DBHost, cfg.DBUser, cfg.DBPass, cfg.DBName, cfg.DBPort)

	return &cfg, nil
}




// EnvToString convert env variable to string
func EnvToString(value *string, key string, defaultValue string) {
	*value = getEnv(key, defaultValue)
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}