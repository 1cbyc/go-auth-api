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

type AuthService struct {
	userRepo                   repository.UserRepository
	refreshTokenRepo           repository.RefreshTokenRepository
	passwordResetTokenRepo     repository.PasswordResetTokenRepository
	emailVerificationTokenRepo repository.EmailVerificationTokenRepository // added for email verification
	config                     *config.Config
}

func NewAuthService(userRepo repository.UserRepository, refreshTokenRepo repository.RefreshTokenRepository, passwordResetTokenRepo repository.PasswordResetTokenRepository, emailVerificationTokenRepo repository.EmailVerificationTokenRepository, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:                   userRepo,
		refreshTokenRepo:           refreshTokenRepo,
		passwordResetTokenRepo:     passwordResetTokenRepo,
		emailVerificationTokenRepo: emailVerificationTokenRepo, // added
		config:                     cfg,
	}
}

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

func (s *AuthService) Register(req models.CreateUserRequest) (*models.AuthResponse, error) {
	if err := validatePasswordPolicy(req.Password); err != nil {
		return nil, err
	}
	if _, err := s.userRepo.GetByUsername(req.Username); err == nil {
		return nil, errors.New("username already exists")
	}

	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return nil, errors.New("email already exists")
	}

	user, err := models.NewUser(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	if err := userService.GenerateAndSendEmailVerification(user); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(rt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

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
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	rt := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(rt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	dbToken, err := s.refreshTokenRepo.GetByToken(refreshToken)
	if err != nil || dbToken == nil {
		return nil, errors.New("invalid refresh token")
	}
	if time.Now().After(dbToken.ExpiresAt) {
		_ = s.refreshTokenRepo.DeleteByToken(refreshToken) // cleanup
		return nil, errors.New("refresh token expired")
	}

	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	accessToken, newRefreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	newRT := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(s.config.JWT.RefreshTokenTTL),
	}
	if err := s.refreshTokenRepo.Create(newRT); err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}
	_ = s.refreshTokenRepo.DeleteByToken(refreshToken)

	user.Sanitize()

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
		User:         *user,
	}, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*models.User, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		return nil, errors.New("token expired")
	}

	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	return user, nil
}

func (s *AuthService) Logout(userID string) error {
	return s.refreshTokenRepo.DeleteByUserID(userID)
}

func (s *AuthService) RequestPasswordReset(email string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.RequestPasswordReset(email)
}

func (s *AuthService) ConfirmPasswordReset(token, newPassword string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.ConfirmPasswordReset(token, newPassword)
}

func (s *AuthService) VerifyEmail(token string) error {
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.VerifyEmail(token)
}

func (s *AuthService) ChangePassword(userID string, req models.ChangePasswordRequest) error {
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		return err
	}
	userService := NewUserService(s.userRepo, s.refreshTokenRepo, s.passwordResetTokenRepo, s.emailVerificationTokenRepo)
	return userService.ChangePassword(userID, req)
}

func (s *AuthService) generateTokens(user *models.User) (string, string, error) {
	now := time.Now()

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

type TokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role,omitempty"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}
