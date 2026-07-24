package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type User struct {
	Id            uuid.UUID `json:"id"`
	Username      string    `json:"username" binding:"required,min=3,max=15"`
	Email         string    `json:"email" binding:"required,email"`
	Password_Hash string    `json:"password_hash" binding:"required,min=6,max=60"`
	User_Role     string    `json:"user_role"`
	Created_at    time.Time `json:"created_at"`
}

type Refresh_token struct {
	Jti        string    `json:"jti"`
	User_ID    uuid.UUID `json:"user_id"`
	Family_ID  uuid.UUID `json:"family_id"`
	Issued_at  time.Time `json:"issued_at"`
	Expires_at time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
}

type AccessClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}
