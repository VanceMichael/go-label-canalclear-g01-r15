package store

import (
	"context"
	"errors"

	"github.com/VanceMichael/go-base-canalclear-g01/internal/auth"
	"github.com/VanceMichael/go-base-canalclear-g01/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type loginRepository struct {
	pool *pgxpool.Pool
}

func (repository loginRepository) FindUserByEmail(ctx context.Context, email string) (auth.User, error) {
	var user auth.User
	err := repository.pool.QueryRow(ctx, `
		SELECT id, tenant_id, email, password_hash, role, disabled, version
		FROM users
		WHERE email = $1
	`, email).Scan(
		&user.ID,
		&user.TenantID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.Disabled,
		&user.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, domain.ErrForbidden
	}
	if err != nil {
		return auth.User{}, err
	}
	return user, nil
}

func (repository loginRepository) CreateSession(ctx context.Context, session auth.Session) error {
	_, err := repository.pool.Exec(ctx, `
		INSERT INTO sessions(
			id,
			user_id,
			tenant_id,
			role,
			token_hash,
			created_at,
			expires_at
		)
		VALUES($1, $2, $3, $4, $5, $6, $7)
	`,
		session.ID,
		session.UserID,
		session.TenantID,
		session.Role,
		session.TokenHash,
		session.CreatedAt,
		session.ExpiresAt,
	)
	return err
}
