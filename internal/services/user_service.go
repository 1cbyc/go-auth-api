package services

import (
	"errors"
	"fmt"

	"go-auth-api/internal/models"
	"go-auth-api/internal/repository"
)

// UserService handles user-related business logic
type UserService struct {
	userRepo repository.UserRepository
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// GetProfile retrieves a user's profile by ID
func (s *UserService) GetProfile(userID string) (*models.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()
	return user, nil
}

// UpdateProfile updates a user's profile
func (s *UserService) UpdateProfile(userID string, req models.UpdateUserRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update user fields
	user.Update(req)

	// Save updated user
	if err := s.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()
	return user, nil
}

// ChangePassword changes a user's password
func (s *UserService) ChangePassword(userID string, req models.ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify current password
	if !user.CheckPassword(req.CurrentPassword) {
		return errors.New("current password is incorrect")
	}

	// Update password
	if err := user.UpdatePassword(req.NewPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Save updated user
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	return nil
}

// ListUsers retrieves a list of users with pagination (admin only)
func (s *UserService) ListUsers(limit, offset int) ([]*models.User, int64, error) {
	users, err := s.userRepo.List(offset, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	total, err := s.userRepo.Count()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Sanitize user data before returning
	for _, user := range users {
		user.Sanitize()
	}

	return users, total, nil
}

// GetUser retrieves a user by ID (admin only)
func (s *UserService) GetUser(userID string) (*models.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()
	return user, nil
}

// UpdateUser updates a user by ID (admin only)
func (s *UserService) UpdateUser(userID string, req models.UpdateUserRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update user fields
	user.Update(req)

	// Save updated user
	if err := s.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()
	return user, nil
}

// DeleteUser deletes a user by ID (admin only)
func (s *UserService) DeleteUser(userID string) error {
	// Check if user exists
	if _, err := s.userRepo.GetByID(userID); err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Delete user
	if err := s.userRepo.Delete(userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}
