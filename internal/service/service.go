package service

import (
	"JWT/internal/config"
	"JWT/internal/domain"
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserRepo interface {
	SaveUser(ctx context.Context, user *domain.User) error
	GetPasswordByUsername(ctx context.Context, username string) (string, error)
	GetUserByUserID(ctx context.Context, user_id string) (*domain.User, error)
}

type RefreshRepo interface {
	GetRefreshByJti(ctx context.Context, jti string) (*domain.Refresh_token, error)
	SaveRefresh(ctx context.Context, refresh string, family uuid.UUID) error
}

type UserService struct {
	usrRepo     UserRepo
	refreshrepo RefreshRepo
	config      *config.Config
}

func NewAurhService(config *config.Config, usrRepo UserRepo, refreshrepo RefreshRepo) *UserService {
	return &UserService{
		usrRepo:     usrRepo,
		refreshrepo: refreshrepo,
		config:      config,
	}
}

func (as *UserService) GenerateTokens(user *domain.User) (string, string, error) {
	access_token := jwt.NewWithClaims(jwt.SigningMethodHS256, domain.AccessClaims{
		UserID: user.Id.String(),
		Email:  user.Email,
		Role:   user.User_Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 15)),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	Singed_access, err := access_token.SignedString(as.config.Jwt_secret)
	if err != nil {
		return "", "", err
	}

	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        uuid.NewString(),
		Subject:   user.Id.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 188)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})

	Singed_refresh, err := refresh_token.SignedString(as.config.Jwt_secret)
	if err != nil {
		return "", "", err
	}
	return Singed_access, Singed_refresh, nil
}

func (as *UserService) Register(ctx context.Context, user *domain.User) error {
	err := as.usrRepo.SaveUser(ctx, user)
	if err != nil {
		return err
	}
	return nil
}

func (as *UserService) Login(ctx context.Context, user *domain.User) (string, string, error) {
	passwd, err := as.usrRepo.GetPasswordByUsername(ctx, user.Username)
	if err != nil {
		return "", "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password_Hash), []byte(passwd))
	if err != nil {
		return "", "", err
	}

	access, refresh, err := as.GenerateTokens(user)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil

}

func (as *UserService) Refresh(ctx context.Context, refresh string) (string, string, error) {
	token, err := jwt.ParseWithClaims(refresh, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.ErrUnsupported
		}
		return nil, nil
	})
	if err != nil {
		return "", "", err
	}

	claims, ok := token.Claims.(jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", "", errors.ErrUnsupported
	}
	user_id := claims.Subject
	jti := claims.ID

	bd_token, err := as.refreshrepo.GetRefreshByJti(ctx, jti)
	if err != nil {
		return "", "", err
	}
	if bd_token.User_ID.String() != user_id || bd_token.Revoked == true {
		return "", "", err
	}

	user, err := as.usrRepo.GetUserByUserID(ctx, user_id)
	if err != nil {
		return "", "", err
	}

	new_access, new_refresh, err := as.GenerateTokens(user)
	if err != nil {
		return "", "", err
	}

	err = as.refreshrepo.SaveRefresh(ctx, new_refresh, bd_token.Family_ID)
	if err != nil {
		return "", "", err
	}

	return new_access, new_refresh, nil

}
