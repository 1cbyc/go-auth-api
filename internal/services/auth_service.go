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
	userRepo repository.UserRepository
	config   *config.Config
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo repository.UserRepository, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		config:   cfg,
	}
}

// Register creates a new user account
func (s *AuthService) Register(req models.CreateUserRequest) (*models.AuthResponse, error) {
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

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
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
	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if !user.CheckPassword(req.Password) {
		return nil, errors.New("invalid credentials")
	}

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
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
	// Parse and validate refresh token
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if token is expired
	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		return nil, errors.New("refresh token expired")
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

	// Generate new tokens
	accessToken, newRefreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

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
