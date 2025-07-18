package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go-auth-api/internal/models"
	"go-auth-api/internal/repository"
)

// UserService handles user-related business logic
type UserService struct {
	userRepo               repository.UserRepository
	refreshTokenRepo       repository.RefreshTokenRepository
	passwordResetTokenRepo repository.PasswordResetTokenRepository // added for password reset
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository, refreshTokenRepo repository.RefreshTokenRepository, passwordResetTokenRepo repository.PasswordResetTokenRepository) *UserService {
	return &UserService{
		userRepo:               userRepo,
		refreshTokenRepo:       refreshTokenRepo,
		passwordResetTokenRepo: passwordResetTokenRepo, // added
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

	// Invalidate all refresh tokens for this user
	if err := s.refreshTokenRepo.DeleteByUserID(userID); err != nil {
		return fmt.Errorf("failed to invalidate refresh tokens: %w", err)
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

// RequestPasswordReset generates a password reset token and simulates sending email
func (s *UserService) RequestPasswordReset(email string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return errors.New("user not found")
	}
	// Generate secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return errors.New("failed to generate token")
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create password reset token
	prt := &models.PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := s.passwordResetTokenRepo.Create(prt); err != nil {
		return errors.New("failed to store password reset token")
	}

	// Simulate sending email (log to console)
	// In production, send email with the token link
	resetLink := "https://your-app/reset-password?token=" + token
	println("[Simulated email] Password reset link for", email, ":", resetLink)
	return nil
}

// ConfirmPasswordReset validates the token and updates the user's password
func (s *UserService) ConfirmPasswordReset(token, newPassword string) error {
	prt, err := s.passwordResetTokenRepo.GetByToken(token)
	if err != nil || prt == nil {
		return errors.New("invalid or expired token")
	}
	if prt.Used {
		return errors.New("token already used")
	}
	if time.Now().After(prt.ExpiresAt) {
		return errors.New("token expired")
	}

	user, err := s.userRepo.GetByID(prt.UserID)
	if err != nil {
		return errors.New("user not found")
	}
	if err := user.UpdatePassword(newPassword); err != nil {
		return errors.New("failed to update password")
	}
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("failed to save user")
	}
	if err := s.refreshTokenRepo.DeleteByUserID(user.ID); err != nil {
		return errors.New("failed to invalidate refresh tokens")
	}
	if err := s.passwordResetTokenRepo.MarkUsed(token); err != nil {
		return errors.New("failed to mark token used")
	}
	return nil
}
