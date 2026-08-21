package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/VanceMichael/go-base-canalclear-g01/internal/domain"
)

// LoginRepository is the persistence boundary needed to authenticate a user.
type LoginRepository interface {
	FindUserByEmail(ctx context.Context, email string) (User, error)
	CreateSession(ctx context.Context, session Session) error
}

// PasswordVerifier allows password verification to be controlled independently
// from persistence. Implementations must observe the supplied context.
type PasswordVerifier interface {
	Verify(ctx context.Context, hash, password string) error
}

type PasswordVerifierFunc func(ctx context.Context, hash, password string) error

func (verify PasswordVerifierFunc) Verify(ctx context.Context, hash, password string) error {
	return verify(ctx, hash, password)
}

type LoginOutcome string

const (
	LoginSucceeded LoginOutcome = "succeeded"
	LoginForbidden LoginOutcome = "forbidden"
	LoginFailed    LoginOutcome = "failed"
)

type LoginObserver interface {
	Finished(email string, outcome LoginOutcome)
}

type LoginObserverFunc func(email string, outcome LoginOutcome)

func (observe LoginObserverFunc) Finished(email string, outcome LoginOutcome) {
	observe(email, outcome)
}

type loginResult struct {
	token   string
	session Session
	err     error
}

type LoginService struct {
	repository LoginRepository
	verifier   PasswordVerifier
	observer   LoginObserver
}

func NewLoginService(repository LoginRepository, verifier PasswordVerifier, observer LoginObserver) (*LoginService, error) {
	if repository == nil {
		return nil, fmt.Errorf("%w: login repository", domain.ErrInvalid)
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: password verifier", domain.ErrInvalid)
	}
	if observer == nil {
		return nil, fmt.Errorf("%w: login observer", domain.ErrInvalid)
	}
	return &LoginService{repository: repository, verifier: verifier, observer: observer}, nil
}

func (service *LoginService) Login(ctx context.Context, email, password string, now time.Time, ttl time.Duration) (string, Session, error) {
	if err := ctx.Err(); err != nil {
		return "", Session{}, err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" || ttl <= 0 {
		return "", Session{}, fmt.Errorf("%w: login request", domain.ErrInvalid)
	}

	// Password hashing cannot always be interrupted, so login completion runs
	// outside the HTTP handler while retaining request-scoped values.
	workContext := context.WithoutCancel(ctx)
	result := make(chan loginResult, 1)
	go func() {
		result <- service.completeLogin(workContext, email, password, now, ttl)
	}()
	select {
	case <-ctx.Done():
		return "", Session{}, ctx.Err()
	case completed := <-result:
		return completed.token, completed.session, completed.err
	}
}

func (service *LoginService) completeLogin(ctx context.Context, email, password string, now time.Time, ttl time.Duration) (completed loginResult) {
	outcome := LoginFailed
	defer func() { service.observer.Finished(email, outcome) }()

	user, err := service.repository.FindUserByEmail(ctx, email)
	if err != nil {
		return loginResult{err: err}
	}
	if user.Disabled {
		outcome = LoginForbidden
		return loginResult{err: domain.ErrForbidden}
	}
	if err := service.verifier.Verify(ctx, user.PasswordHash, password); err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			outcome = LoginForbidden
		}
		return loginResult{err: err}
	}

	session, token, err := NewSession(user, now, ttl)
	if err != nil {
		return loginResult{err: err}
	}
	if err := service.repository.CreateSession(ctx, session); err != nil {
		return loginResult{err: err}
	}
	outcome = LoginSucceeded
	return loginResult{token: token, session: session}
}
