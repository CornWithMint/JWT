package repo

import (
	"JWT/internal/domain"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{
		db: pool,
	}
}

func (usrRepo *UserRepo) SaveUser(ctx context.Context, user *domain.User) error {
	_, err := usrRepo.db.Exec(ctx, `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)`, user.Username, user.Email, user.Password_Hash)
	if err != nil {
		return err
	}
	return nil

}

func (UsrRepo *UserRepo) GetPasswordByUsername(ctx context.Context, username string) (string, error) {
	row := UsrRepo.db.QueryRow(ctx, `SELECT password_hash FROM users where username=$1 `, username)

	password_hash := ""
	err := row.Scan(&password_hash)
	if err != nil {
		return "", err
	}
	return password_hash, nil
}

func (UsrRepo *UserRepo) GetUserByUserID(ctx context.Context, user_id string) (*domain.User, error) {
	row := UsrRepo.db.QueryRow(ctx, `SELECT id, email, user_role FROM users where id=$1 `, user_id)

	user := &domain.User{}
	err := row.Scan(&user.Id, &user.Email, &user.User_Role)
	if err != nil {
		return nil, err
	}
	return user, nil
}


