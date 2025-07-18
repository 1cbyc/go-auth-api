package services

import (
	"errors"
	"fmt"
	"time"

	"go-auth-api/internal/config"
	"go-auth-api/internal/models"
	"go-auth-api/internal/repository"

	"github.com/golang-jwt/jwt/v5"
)

// AuthService handles authentication-related business logic
type AuthService struct {
	userRepo                   repository.UserRepository
	refreshTokenRepo           repository.RefreshTokenRepository
	passwordResetTokenRepo     repository.PasswordResetTokenRepository
	emailVerificationTokenRepo repository.EmailVerificationTokenRepository // added for email verification
	config                     *config.Config
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo repository.UserRepository, refreshTokenRepo repository.RefreshTokenRepository, passwordResetTokenRepo repository.PasswordResetTokenRepository, emailVerificationTokenRepo repository.EmailVerificationTokenRepository, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:                   userRepo,
		refreshTokenRepo:           refreshTokenRepo,
		passwordResetTokenRepo:     passwordResetTokenRepo,
		emailVerificationTokenRepo: emailVerificationTokenRepo, // added
		config:                     cfg,
	}
}

// Helper: password policy enforcement
func validatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case c >= 33 && c <= 47 || c >= 58 && c <= 64 || c >= 91 && c <= 96 || c >= 123 && c <= 126:
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain upper, lower, digit, and special char")
	}
	return nil
}

// Register creates a new user account
func (s *AuthService) Register(req models.CreateUserRequest) (*models.AuthResponse, error) {
	if err := validatePasswordPolicy(req.Password); err != nil {
		return nil, err
	}
	// Check if user already exists
	if _, err := s.userRepo.GetByUsername(req.Username); err == nil {
		return nil, errors.New("username already exists")
	}

	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return nil, errors.New("email already exists")
	}

	// Create new user
	user, err := models.NewUser(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Save user to repository
	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Generate and send email verification
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	if err := userService.GenerateAndSendEmailVerification(user); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token in DB
	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(rt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(req models.LoginRequest) (*models.AuthResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if user.LockoutUntil != nil && user.LockoutUntil.After(time.Now()) {
		return nil, errors.New("account is locked. Try again later")
	}
	if !user.CheckPassword(req.Password) {
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= 5 {
			lockout := time.Now().Add(15 * time.Minute)
			user.LockoutUntil = &lockout
		}
		s.userRepo.Update(user)
		return nil, errors.New("invalid credentials")
	}
	user.FailedLoginAttempts = 0
	user.LockoutUntil = nil
	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token in DB
	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(rt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Sanitize user data before returning
	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

// RefreshToken generates new access token using refresh token
func (s *AuthService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	// Check refresh token in DB
	dbToken, err := s.refreshTokenRepo.GetByToken(refreshToken)
	if err != nil || dbToken == nil {
		return nil, errors.New("invalid refresh token")
	}
	if time.Now().After(dbToken.ExpiresAt) {
		_ = s.refreshTokenRepo.DeleteByToken(refreshToken) // cleanup
		return nil, errors.New("refresh token expired")
	}

	// Parse and validate refresh token
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get user from repository
	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Generate new tokens
	accessToken, newRefreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store new refresh token in DB, delete old one
	newRT := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(newRT); err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}
	_ = s.refreshTokenRepo.DeleteByToken(refreshToken)

	// Sanitize user data before returning
	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

// ValidateToken validates an access token and returns user claims
func (s *AuthService) ValidateToken(tokenString string) (*models.User, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	// Check if token is expired
	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		return nil, errors.New("token expired")
	}

	// Get user from repository
	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	return user, nil
}

// Logout invalidates all refresh tokens for the user
func (s *AuthService) Logout(userID string) error {
	return s.refreshTokenRepo.DeleteByUserID(userID)
}

// RequestPasswordReset delegates to UserService for password reset request
func (s *AuthService) RequestPasswordReset(email string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.RequestPasswordReset(email)
}

// ConfirmPasswordReset delegates to UserService for password reset confirmation
func (s *AuthService) ConfirmPasswordReset(token, newPassword string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.ConfirmPasswordReset(token, newPassword)
}

// VerifyEmail delegates to UserService for email verification
func (s *AuthService) VerifyEmail(token string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.VerifyEmail(token)
}

// ChangePassword enforces password policy
func (s *AuthService) ChangePassword(userID string, req models.ChangePasswordRequest) error {
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		return err
	}
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.ChangePassword(userID, req)
}

// generateTokens generates access and refresh tokens for a user
func (s *AuthService) generateTokens(user *models.User) (string, string, error) {
	now := time.Now()

	// Generate access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"type":    "access",
		"iat":     now.Unix(),
		"exp":     now.Add(s.config.JWT.AccessTokenTTL).Unix(),
		"iss":     s.config.JWT.Issuer,
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"type":    "refresh",
		"iat":     now.Unix(),
		"exp":     now.Add(s.config.JWT.RefreshTokenTTL).Unix(),
		"iss":     s.config.JWT.Issuer,
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// parseToken parses and validates a JWT token
func (s *AuthService) parseToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// TokenClaims represents the claims in a JWT token
type TokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role,omitempty"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}
