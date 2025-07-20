package repository

import (
	"errors"
	"sync"

	"go-auth-api/internal/models"
)

type UserRepository interface {
	Create(user *models.User) error
	GetByID(id string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	Delete(id string) error
	List(offset, limit int) ([]*models.User, error)
	Count() (int64, error)
	LogUserActivity(userID, action, details string) error
	ListUserActivityLogs(userID string, limit, offset int) ([]*models.UserActivityLog, error)
}

type RefreshTokenRepository interface {
	Create(token *models.RefreshToken) error
	GetByToken(token string) (*models.RefreshToken, error)
	DeleteByToken(token string) error
	DeleteByUserID(userID string) error
}

type PasswordResetTokenRepository interface {
	Create(token *models.PasswordResetToken) error
	GetByToken(token string) (*models.PasswordResetToken, error)
	MarkUsed(token string) error
	DeleteByUserID(userID string) error
}

type EmailVerificationTokenRepository interface {
	Create(token *models.EmailVerificationToken) error
	GetByToken(token string) (*models.EmailVerificationToken, error)
	MarkUsed(token string) error
	DeleteByUserID(userID string) error
}

type InMemoryUserRepository struct {
	users map[string]*models.User
	mutex sync.RWMutex
}

func NewInMemoryUserRepository() UserRepository {
	repo := &InMemoryUserRepository{
		users: make(map[string]*models.User),
	}

	repo.initializeDefaultUsers()

	return repo
}

func (r *InMemoryUserRepository) Create(user *models.User) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for _, existingUser := range r.users {
		if existingUser.Username == user.Username {
			return errors.New("username already exists")
		}
		if existingUser.Email == user.Email {
			return errors.New("email already exists")
		}
	}

	r.users[user.ID] = user
	return nil
}

func (r *InMemoryUserRepository) GetByID(id string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}

	userCopy := *user
	return &userCopy, nil
}

func (r *InMemoryUserRepository) GetByUsername(username string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.users {
		if user.Username == username {
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, errors.New("user not found")
}

func (r *InMemoryUserRepository) GetByEmail(email string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.users {
		if user.Email == email {
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, errors.New("user not found")
}

func (r *InMemoryUserRepository) Update(user *models.User) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.users[user.ID]; !exists {
		return errors.New("user not found")
	}

	for id, existingUser := range r.users {
		if id == user.ID {
			continue // Skip the user being updated
		}
		if existingUser.Username == user.Username {
			return errors.New("username already exists")
		}
		if existingUser.Email == user.Email {
			return errors.New("email already exists")
		}
	}

	r.users[user.ID] = user
	return nil
}

func (r *InMemoryUserRepository) Delete(id string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.users[id]; !exists {
		return errors.New("user not found")
	}

	delete(r.users, id)
	return nil
}

func (r *InMemoryUserRepository) List(offset, limit int) ([]*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	users := make([]*models.User, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	if offset >= len(users) {
		return []*models.User{}, nil
	}

	end := offset + limit
	if end > len(users) {
		end = len(users)
	}

	result := make([]*models.User, 0, end-offset)
	for i := offset; i < end; i++ {
		userCopy := *users[i]
		result = append(result, &userCopy)
	}

	return result, nil
}

func (r *InMemoryUserRepository) Count() (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return int64(len(r.users)), nil
}

func (r *InMemoryUserRepository) initializeDefaultUsers() {
	adminUser, _ := models.NewUser(models.CreateUserRequest{
		Username:  "admin",
		Email:     "admin@example.com",
		Password:  "adminpass123",
		FirstName: "Admin",
		LastName:  "User",
		Role:      "admin",
	})
	r.users[adminUser.ID] = adminUser

	regularUser, _ := models.NewUser(models.CreateUserRequest{
		Username:  "user",
		Email:     "user@example.com",
		Password:  "userpass123",
		FirstName: "Regular",
		LastName:  "User",
		Role:      "user",
	})
	r.users[regularUser.ID] = regularUser
}

func (r *InMemoryUserRepository) LogUserActivity(userID, action, details string) error {
	return nil // no-op for in-memory
}

func (r *InMemoryUserRepository) ListUserActivityLogs(userID string, limit, offset int) ([]*models.UserActivityLog, error) {
	return []*models.UserActivityLog{}, nil // no-op for in-memory
}
