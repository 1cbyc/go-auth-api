package handlers

import (
	"errors"
	"net/http"
	"strings"

	"go-auth-api/internal/models"
	"go-auth-api/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
	authService *services.AuthService
	logger      *logrus.Logger
}

func NewAuthHandler(authService *services.AuthService, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode registration request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := validateCreateUserRequest(req); err != nil {
		h.logger.WithError(err).Error("Invalid registration request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.Register(req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to register user")
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode login request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := validateLoginRequest(req); err != nil {
		h.logger.WithError(err).Error("Invalid login request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.Login(req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to authenticate user")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode refresh token request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.RefreshToken == "" {
		h.logger.Error("Empty refresh token")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.WithError(err).Error("Failed to refresh token")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}
	if err := h.authService.Logout(userID.(string)); err != nil {
		h.logger.WithError(err).Error("Failed to logout user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

func (h *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var req models.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode password reset request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Email == "" {
		h.logger.Error("Empty email in password reset request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}
	if err := h.authService.RequestPasswordReset(req.Email); err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		h.logger.WithError(err).Error("Failed to request password reset")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to request password reset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent (simulated)"})
}

func (h *AuthHandler) ConfirmPasswordReset(c *gin.Context) {
	var req models.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode password reset confirm request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		h.logger.Error("Empty token or new password in password reset confirm request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token and new password are required"})
		return
	}
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password must be at least 8 characters long"})
		return
	}
	if err := h.authService.ConfirmPasswordReset(req.Token, req.NewPassword); err != nil {
		h.logger.WithError(err).Error("Failed to confirm password reset")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req models.EmailVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode email verification request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Token == "" {
		h.logger.Error("Empty token in email verification request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}
	if err := h.authService.VerifyEmail(req.Token); err != nil {
		h.logger.WithError(err).Error("Failed to verify email")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

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
	if !strings.Contains(req.Email, "@") {
		return errors.New("invalid email format")
	}

	if req.Password == "" {
		return errors.New("password is required")
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if req.FirstName == "" {
		return errors.New("first_name is required")
	}

	if req.LastName == "" {
		return errors.New("last_name is required")
	}

	return nil
}

func validateLoginRequest(req models.LoginRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if !strings.Contains(req.Email, "@") {
		return errors.New("invalid email format")
	}

	if req.Password == "" {
		return errors.New("password is required")
	}

	return nil
}
