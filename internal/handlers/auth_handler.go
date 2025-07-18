package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/1cbyc/go-auth-api/internal/models"
	"github.com/1cbyc/go-auth-api/internal/services"
	"github.com/sirupsen/logrus"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService *services.AuthService
	logger      *logrus.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService *services.AuthService, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

// Register handles user registration
func (h *AuthHandler) Register() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req models.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode registration request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate request
		if err := validateCreateUserRequest(req); err != nil {
			h.logger.WithError(err).Error("Invalid registration request")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Register user
		response, err := h.authService.Register(req)
		if err != nil {
			h.logger.WithError(err).Error("Failed to register user")
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	})
}

// Login handles user login
func (h *AuthHandler) Login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req models.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode login request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate request
		if err := validateLoginRequest(req); err != nil {
			h.logger.WithError(err).Error("Invalid login request")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Authenticate user
		response, err := h.authService.Login(req)
		if err != nil {
			h.logger.WithError(err).Error("Failed to authenticate user")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req models.RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode refresh token request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate request
		if req.RefreshToken == "" {
			h.logger.Error("Empty refresh token")
			http.Error(w, "Refresh token is required", http.StatusBadRequest)
			return
		}

		// Refresh token
		response, err := h.authService.RefreshToken(req.RefreshToken)
		if err != nil {
			h.logger.WithError(err).Error("Failed to refresh token")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In a real application, you might want to blacklist the refresh token
		// For now, we'll just return a success response

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Successfully logged out",
		})
	})
}

// Helper functions for validation
func validateCreateUserRequest(req models.CreateUserRequest) error {
	if req.Username == "" {
		return errors.New("username is required")
	}
	if len(req.Username) < 3 {
		return errors.New("username must be at least 3 characters long")
	}
	if len(req.Username) > 50 {
		return errors.New("username must be at most 50 characters long")
	}

	if req.Email == "" {
		return errors.New("email is required")
	}
	// Basic email validation
	if !strings.Contains(req.Email, "@") {
		return errors.New("invalid email format")
	}

	if req.Password == "" {
		return errors.New("password is required")
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	return nil
}

func validateLoginRequest(req models.LoginRequest) error {
	if req.Username == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	return nil
}
