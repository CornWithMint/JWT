package repo

import (
	"JWT/internal/domain"
	"context"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshRepo struct {
	db *pgxpool.Pool
}

func NewRefreshRepo(pool *pgxpool.Pool) *RefreshRepo {
	return &RefreshRepo{
		db: pool,
	}
}
func (RfrRepo *RefreshRepo) ParceToken(my_token string) (*jwt.Token, error) {
	secret := os.Getenv("SECRET_JWT")
	token, err := jwt.ParseWithClaims(my_token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("Bad token")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("Bad token")
	}
	return token, nil
}

func (RfrRepo *RefreshRepo) SaveRefresh(ctx context.Context, refresh string, family uuid.UUID) error {
	token, err := RfrRepo.ParceToken(refresh)
	if err != nil {
		return err
	}

	claims, ok := token.Claims.(jwt.RegisteredClaims)
	if !token.Valid || !ok {
		return errors.ErrUnsupported
	}

	_, err = RfrRepo.db.Exec(ctx, `INSERT INTO refresh_tokens (jti, user_id, family_id, expires_at) VALUES ($1,$2,$3,$4)`,
		claims.ID, claims.Subject, family, claims.ExpiresAt)
	if err != nil {
		return err
	}
	return nil
}

func (RfrRepo *RefreshRepo) GetRefreshByJti(ctx context.Context, jti string) (*domain.Refresh_token, error) {
	row := RfrRepo.db.QueryRow(ctx, `SELECT user_id, family_id, expires_at,revoked FROM refresh_tokens where jti=$1 `, jti)

	refresh := &domain.Refresh_token{}
	err := row.Scan(&refresh.User_ID, &refresh.Family_ID, refresh.Expires_at, refresh.Revoked)
	if err != nil {
		return nil, err
	}

	return refresh, nil
}

func (RfrRepo *RefreshRepo) ChangeRevoked(ctx context.Context, jti string) error {
	_, err := RfrRepo.db.Exec(ctx, `UPDATE refresh_tokens SET revoked = $1 WHERE jti = $2`, true, jti)
	if err != nil {
		return err
	}
	return nil
}
