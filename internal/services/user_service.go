package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go-auth-api/internal/models"
	"go-auth-api/internal/repository"

	"github.com/pquerna/otp/totp"
)

// UserService handles user-related business logic
type UserService struct {
	userRepo                   repository.UserRepository
	refreshTokenRepo           repository.RefreshTokenRepository
	passwordResetTokenRepo     repository.PasswordResetTokenRepository
	emailVerificationTokenRepo repository.EmailVerificationTokenRepository // added for email verification
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository, refreshTokenRepo repository.RefreshTokenRepository, passwordResetTokenRepo repository.PasswordResetTokenRepository, emailVerificationTokenRepo repository.EmailVerificationTokenRepository) *UserService {
	return &UserService{
		userRepo:                   userRepo,
		refreshTokenRepo:           refreshTokenRepo,
		passwordResetTokenRepo:     passwordResetTokenRepo,
		emailVerificationTokenRepo: emailVerificationTokenRepo, // added
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

// DeleteUser deletes a user by ID (soft delete by default)
func (s *UserService) DeleteUser(userID string) error {
	// Check if user exists
	if _, err := s.userRepo.GetByID(userID); err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	// Soft delete (GORM)
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

// GenerateAndSendEmailVerification generates a verification token and simulates sending email
func (s *UserService) GenerateAndSendEmailVerification(user *models.User) error {
	// Generate secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return errors.New("failed to generate token")
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create email verification token
	evt := &models.EmailVerificationToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.emailVerificationTokenRepo.Create(evt); err != nil {
		return errors.New("failed to store email verification token")
	}

	// Simulate sending email (log to console)
	verifyLink := "https://your-app/verify-email?token=" + token
	println("[Simulated email] Email verification link for", user.Email, ":", verifyLink)
	return nil
}

// VerifyEmail validates the token and marks the user as verified
func (s *UserService) VerifyEmail(token string) error {
	evt, err := s.emailVerificationTokenRepo.GetByToken(token)
	if err != nil || evt == nil {
		return errors.New("invalid or expired token")
	}
	if evt.Used {
		return errors.New("token already used")
	}
	if time.Now().After(evt.ExpiresAt) {
		return errors.New("token expired")
	}

	user, err := s.userRepo.GetByID(evt.UserID)
	if err != nil {
		return errors.New("user not found")
	}
	if user.IsEmailVerified {
		return errors.New("email already verified")
	}
	user.IsEmailVerified = true
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("failed to update user")
	}
	if err := s.emailVerificationTokenRepo.MarkUsed(token); err != nil {
		return errors.New("failed to mark token used")
	}
	return nil
}

// SetupTwoFA generates a TOTP secret and returns QR/otpauth URL
func (s *UserService) SetupTwoFA(userID string) (string, string, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return "", "", errors.New("user not found")
	}
	if user.TwoFAEnabled {
		return "", "", errors.New("2FA already enabled")
	}
	secret := base64.StdEncoding.EncodeToString([]byte(userID + time.Now().String()))
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoAuthAPI",
		AccountName: user.Email,
		Secret:      []byte(secret),
	})
	if err != nil {
		return "", "", errors.New("failed to generate TOTP secret")
	}
	user.TwoFASecret = key.Secret()
	if err := s.userRepo.Update(user); err != nil {
		return "", "", errors.New("failed to save 2FA secret")
	}
	return key.Secret(), key.URL(), nil
}

// VerifyTwoFA verifies a TOTP code and enables 2FA
func (s *UserService) VerifyTwoFA(userID, code string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}
	if user.TwoFASecret == "" {
		return errors.New("2FA not set up")
	}
	if !totp.Validate(code, user.TwoFASecret) {
		return errors.New("invalid 2FA code")
	}
	user.TwoFAEnabled = true
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("failed to enable 2FA")
	}
	return nil
}

// DisableTwoFA disables 2FA for the user
func (s *UserService) DisableTwoFA(userID string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}
	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("failed to disable 2FA")
	}
	return nil
}

// UpdateAvatar updates the user's avatar URL
func (s *UserService) UpdateAvatar(userID, avatarURL string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}
	user.AvatarURL = avatarURL
	return s.userRepo.Update(user)
}

// GetPreferences returns the user's preferences (as JSON string)
func (s *UserService) GetPreferences(userID string) (string, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return "", err
	}
	return user.Preferences, nil
}

// UpdatePreferences updates the user's preferences (as JSON string)
func (s *UserService) UpdatePreferences(userID, prefs string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}
	user.Preferences = prefs
	return s.userRepo.Update(user)
}

// LogUserActivity logs a user action
func (s *UserService) LogUserActivity(userID, action, details string) error {
	return s.userRepo.LogUserActivity(userID, action, details)
}

// ListUserActivityLogs returns activity logs for a user (admin)
func (s *UserService) ListUserActivityLogs(userID string, limit, offset int) ([]*models.UserActivityLog, error) {
	return s.userRepo.ListUserActivityLogs(userID, limit, offset)
}

// BulkUpdateUsers updates multiple users (admin)
func (s *UserService) BulkUpdateUsers(updates []models.UpdateUserRequest) (map[string]interface{}, error) {
	results := make(map[string]string)
	for _, req := range updates {
		if req.Username == "" && req.Email == "" {
			continue
		}
		var user *models.User
		var err error
		if req.Username != "" {
			user, err = s.userRepo.GetByUsername(req.Username)
		} else {
			user, err = s.userRepo.GetByEmail(req.Email)
		}
		if err != nil {
			results[req.Username+req.Email] = "not found"
			continue
		}
		user.Update(req)
		if err := s.userRepo.Update(user); err != nil {
			results[user.ID] = "update failed"
			continue
		}
		results[user.ID] = "updated"
	}
	return map[string]interface{}{"summary": results}, nil
}

// BulkDeleteUsers deletes multiple users (admin)
func (s *UserService) BulkDeleteUsers(userIDs []string) (map[string]interface{}, error) {
	results := make(map[string]string)
	for _, id := range userIDs {
		if err := s.userRepo.Delete(id); err != nil {
			results[id] = "delete failed"
			continue
		}
		results[id] = "deleted"
	}
	return map[string]interface{}{"summary": results}, nil
}
