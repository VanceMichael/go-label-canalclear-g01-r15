package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type loginRepositoryStub struct {
	mu             sync.Mutex
	user           User
	createdSession []Session
}

func (repository *loginRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	return repository.user, nil
}

func (repository *loginRepositoryStub) CreateSession(_ context.Context, session Session) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.createdSession = append(repository.createdSession, session)
	return nil
}

func (repository *loginRepositoryStub) createdCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return len(repository.createdSession)
}

type controlledPasswordVerifier struct {
	started chan struct{}
	release chan struct{}
	ended   chan struct{}
}

func (verifier *controlledPasswordVerifier) Verify(_ context.Context, _, _ string) error {
	close(verifier.started)
	<-verifier.release
	close(verifier.ended)
	return nil
}

func TestCancelledLoginNeverPersistsSession(t *testing.T) {
	repository := &loginRepositoryStub{user: User{
		ID:           "dispatcher-cancelled-login",
		TenantID:     "demo-port",
		Email:        "dispatcher@canalclear.test",
		PasswordHash: "not-used-by-controlled-verifier",
		Role:         RoleDispatcher,
		Version:      1,
	}}
	verifier := &controlledPasswordVerifier{
		started: make(chan struct{}),
		release: make(chan struct{}),
		ended:   make(chan struct{}),
	}
	attemptFinished := make(chan struct{})
	service, err := NewLoginService(repository, verifier, LoginObserverFunc(func(string, LoginOutcome) {
		close(attemptFinished)
	}))
	if err != nil {
		t.Fatal(err)
	}

	requestContext, cancelRequest := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := service.Login(requestContext, repository.user.Email, "valid-password", time.Now().UTC(), time.Hour)
		result <- err
	}()

	<-verifier.started
	cancelRequest()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("login error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("login did not return after the request was cancelled")
	}
	if count := repository.createdCount(); count != 0 {
		t.Fatalf("created sessions before password verification ended = %d, want 0", count)
	}

	close(verifier.release)
	<-verifier.ended
	<-attemptFinished
	if count := repository.createdCount(); count != 0 {
		t.Fatalf("created sessions after the cancelled attempt finished = %d, want 0", count)
	}
}
