package repository

import (
	"errors"
	"sync"

	"go-auth-api/internal/models"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(user *models.User) error
	GetByID(id string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	Delete(id string) error
	List(offset, limit int) ([]*models.User, error)
	Count() (int64, error)
}

// RefreshTokenRepository defines the interface for refresh token operations
// (added for JWT refresh token persistence)
type RefreshTokenRepository interface {
	Create(token *models.RefreshToken) error
	GetByToken(token string) (*models.RefreshToken, error)
	DeleteByToken(token string) error
	DeleteByUserID(userID string) error
}

// PasswordResetTokenRepository defines the interface for password reset token operations
// (for password reset flow)
type PasswordResetTokenRepository interface {
	Create(token *models.PasswordResetToken) error
	GetByToken(token string) (*models.PasswordResetToken, error)
	MarkUsed(token string) error
	DeleteByUserID(userID string) error
}

// EmailVerificationTokenRepository defines the interface for email verification token operations
// (for email verification flow)
type EmailVerificationTokenRepository interface {
	Create(token *models.EmailVerificationToken) error
	GetByToken(token string) (*models.EmailVerificationToken, error)
	MarkUsed(token string) error
	DeleteByUserID(userID string) error
}

// InMemoryUserRepository implements UserRepository with in-memory storage
type InMemoryUserRepository struct {
	users map[string]*models.User
	mutex sync.RWMutex
}

// NewInMemoryUserRepository creates a new in-memory user repository
func NewInMemoryUserRepository() UserRepository {
	repo := &InMemoryUserRepository{
		users: make(map[string]*models.User),
	}

	// Initialize with some default users for testing
	repo.initializeDefaultUsers()

	return repo
}

// Create adds a new user to the repository
func (r *InMemoryUserRepository) Create(user *models.User) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if username already exists
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

// GetByID retrieves a user by ID
func (r *InMemoryUserRepository) GetByID(id string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}

	// Return a copy to avoid external modifications
	userCopy := *user
	return &userCopy, nil
}

// GetByUsername retrieves a user by username
func (r *InMemoryUserRepository) GetByUsername(username string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.users {
		if user.Username == username {
			// Return a copy to avoid external modifications
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, errors.New("user not found")
}

// GetByEmail retrieves a user by email
func (r *InMemoryUserRepository) GetByEmail(email string) (*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.users {
		if user.Email == email {
			// Return a copy to avoid external modifications
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, errors.New("user not found")
}

// Update updates an existing user
func (r *InMemoryUserRepository) Update(user *models.User) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.users[user.ID]; !exists {
		return errors.New("user not found")
	}

	// Check for username/email conflicts with other users
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

// Delete removes a user from the repository
func (r *InMemoryUserRepository) Delete(id string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.users[id]; !exists {
		return errors.New("user not found")
	}

	delete(r.users, id)
	return nil
}

// List retrieves a list of users with pagination
func (r *InMemoryUserRepository) List(offset, limit int) ([]*models.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	users := make([]*models.User, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	// Simple pagination (in a real implementation, you'd want proper sorting)
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

// Count returns the total number of users
func (r *InMemoryUserRepository) Count() (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return int64(len(r.users)), nil
}

// initializeDefaultUsers creates some default users for testing
func (r *InMemoryUserRepository) initializeDefaultUsers() {
	// Create admin user
	adminUser, _ := models.NewUser(models.CreateUserRequest{
		Username:  "admin",
		Email:     "admin@example.com",
		Password:  "adminpass123",
		FirstName: "Admin",
		LastName:  "User",
		Role:      "admin",
	})
	r.users[adminUser.ID] = adminUser

	// Create regular user
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
