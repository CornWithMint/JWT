package config

import "os"

type Config struct {
	Jwt_secret string
}

func NewConfig() *Config {
	return &Config{
		Jwt_secret: Getenv("JWT_SECRET", "Random_key"),
	}
}

func Getenv(value, defaulVal string) string {
	if val, ok := os.LookupEnv(value); ok {
		return val
	}
	return defaulVal
}
