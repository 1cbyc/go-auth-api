package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"go-auth-api/internal/models"
	"go-auth-api/internal/services"
	"go-auth-api/internal/storage"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	userService *services.UserService
	logger      *logrus.Logger
	storage     *storage.Storage // added for file storage
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *services.UserService, logger *logrus.Logger, storage *storage.Storage) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
		storage:     storage, // added
	}
}

// GetProfile retrieves the current user's profile
// @Summary Get user profile
// @Description Get the current authenticated user's profile information
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.User "User profile retrieved successfully"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal server error"
// @Router /users/profile [get]
func (h *UserHandler) GetProfile(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user profile
	profile, err := h.userService.GetProfile(userID.(string))
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user profile")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, profile)
}

// UpdateProfile updates the current user's profile
// @Summary Update user profile
// @Description Update the current authenticated user's profile information
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param profile body models.UpdateUserRequest true "Profile update data"
// @Success 200 {object} models.User "Profile updated successfully"
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal server error"
// @Router /users/profile [put]
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse request body
	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update profile request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Update user profile
	updatedUser, err := h.userService.UpdateProfile(userID.(string), req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user profile")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, updatedUser)
}

// ChangePassword changes the current user's password
// @Summary Change password
// @Description Change the current authenticated user's password
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param password body models.ChangePasswordRequest true "Password change data"
// @Success 200 {object} map[string]string "Password changed successfully"
// @Failure 400 {string} string "Invalid request data or incorrect current password"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal server error"
// @Router /users/change-password [post]
func (h *UserHandler) ChangePassword(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse request body
	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode change password request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate request
	if err := validateChangePasswordRequest(req); err != nil {
		h.logger.WithError(err).Error("Invalid change password request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Change password
	if err := h.userService.ChangePassword(userID.(string), req); err != nil {
		h.logger.WithError(err).Error("Failed to change password")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// ListUsers retrieves a list of users with pagination (admin only)
// @Summary List users
// @Description Get a paginated list of all users (admin only)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param limit query int false "Number of users to return (default: 10)"
// @Param offset query int false "Number of users to skip (default: 0)"
// @Success 200 {object} map[string]interface{} "Users list retrieved successfully"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - Admin role required"
// @Failure 500 {string} string "Internal server error"
// @Router /admin/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	// Parse query parameters
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")

	limit := 10 // default limit
	offset := 0 // default offset

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get users
	users, total, err := h.userService.ListUsers(limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetUser retrieves a specific user by ID (admin only)
// @Summary Get user by ID
// @Description Get a specific user's information by ID (admin only)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.User "User retrieved successfully"
// @Failure 400 {string} string "Invalid user ID"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - Admin role required"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /admin/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Get user
	user, err := h.userService.GetUser(userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user")
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, user)
}

// UpdateUser updates a specific user by ID (admin only)
// @Summary Update user by ID
// @Description Update a specific user's information by ID (admin only)
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body models.UpdateUserRequest true "User update data"
// @Success 200 {object} models.User "User updated successfully"
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - Admin role required"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /admin/users/{id} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Parse request body
	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update user request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Update user
	updatedUser, err := h.userService.UpdateProfile(userID, req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, updatedUser)
}

// DeleteUser deletes a specific user by ID (admin only)
// @Summary Delete user by ID
// @Description Delete a specific user by ID (admin only)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string "User deleted successfully"
// @Failure 400 {string} string "Invalid user ID"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - Admin role required"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /admin/users/{id} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Delete user
	if err := h.userService.DeleteUser(userID); err != nil {
		h.logger.WithError(err).Error("Failed to delete user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// SetupTwoFA handles 2FA setup
// @Summary Setup 2FA
// @Description Generate TOTP secret and QR code for 2FA
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} models.TwoFASetupResponse "2FA setup info"
// @Failure 400 {string} string "Invalid request data"
// @Router /users/2fa/setup [post]
func (h *UserHandler) SetupTwoFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	secret, otpauth, err := h.userService.SetupTwoFA(userID.(string))
	if err != nil {
		h.logger.WithError(err).Error("Failed to setup 2FA")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.TwoFASetupResponse{Secret: secret, OTPAuth: otpauth})
}

// VerifyTwoFA handles 2FA verification
// @Summary Verify 2FA
// @Description Verify TOTP code and enable 2FA
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.TwoFAVerifyRequest true "2FA verify request"
// @Success 200 {object} map[string]string "2FA enabled"
// @Failure 400 {string} string "Invalid request data or code"
// @Router /users/2fa/verify [post]
func (h *UserHandler) VerifyTwoFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	var req models.TwoFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode 2FA verify request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code is required"})
		return
	}
	if err := h.userService.VerifyTwoFA(userID.(string), req.Code); err != nil {
		h.logger.WithError(err).Error("Failed to verify 2FA")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "2FA enabled"})
}

// DisableTwoFA handles disabling 2FA
// @Summary Disable 2FA
// @Description Disable 2FA for the user
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "2FA disabled"
// @Failure 400 {string} string "Invalid request data"
// @Router /users/2fa/disable [post]
func (h *UserHandler) DisableTwoFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	if err := h.userService.DisableTwoFA(userID.(string)); err != nil {
		h.logger.WithError(err).Error("Failed to disable 2FA")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "2FA disabled"})
}

// UploadAvatar handles avatar upload
// @Summary Upload avatar
// @Description Upload a profile picture
// @Tags users
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param avatar formData file true "Avatar image"
// @Success 200 {object} map[string]string "Avatar uploaded"
// @Failure 400 {string} string "Invalid request data"
// @Router /users/avatar [post]
func (h *UserHandler) UploadAvatar(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	file, fileHeader, err := c.Request.FormFile("avatar")
	if err != nil {
		h.logger.WithError(err).Error("Failed to get avatar file")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file"})
		return
	}
	defer file.Close()
	dest := "avatars/" + userID.(string) + "_" + fileHeader.Filename
	url, err := h.storage.UploadFile(c.Request.Context(), file, fileHeader, dest)
	if err != nil {
		h.logger.WithError(err).Error("Failed to upload avatar file")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file"})
		return
	}
	if err := h.userService.UpdateAvatar(userID.(string), url); err != nil {
		h.logger.WithError(err).Error("Failed to update user avatar")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"avatar_url": url})
}

// GetAvatar serves the user's avatar
// @Summary Get avatar
// @Description Get the user's profile picture
// @Tags users
// @Security BearerAuth
// @Produce image/*
// @Success 200 {file} file "Avatar image"
// @Failure 404 {string} string "Avatar not found"
// @Router /users/avatar [get]
func (h *UserHandler) GetAvatar(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user, err := h.userService.GetProfile(userID.(string))
	if err != nil || user.AvatarURL == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Avatar not found"})
		return
	}
	c.File("." + user.AvatarURL)
}

// GetPreferences returns the user's preferences
// @Summary Get user preferences
// @Description Get the current user's preferences
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "User preferences"
// @Failure 401 {string} string "Unauthorized"
// @Router /users/preferences [get]
func (h *UserHandler) GetPreferences(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	prefs, err := h.userService.GetPreferences(userID.(string))
	if err != nil {
		h.logger.WithError(err).Error("Failed to get preferences")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get preferences"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"preferences": prefs})
}

// UpdatePreferences updates the user's preferences
// @Summary Update user preferences
// @Description Update the current user's preferences
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param preferences body map[string]interface{} true "Preferences JSON"
// @Success 200 {object} map[string]string "Preferences updated"
// @Failure 400 {string} string "Invalid request data"
// @Router /users/preferences [put]
func (h *UserHandler) UpdatePreferences(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	var prefs map[string]interface{}
	if err := c.ShouldBindJSON(&prefs); err != nil {
		h.logger.WithError(err).Error("Failed to decode preferences")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	prefsJSON, err := json.Marshal(prefs)
	if err != nil {
		h.logger.WithError(err).Error("Failed to marshal preferences")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid preferences"})
		return
	}
	if err := h.userService.UpdatePreferences(userID.(string), string(prefsJSON)); err != nil {
		h.logger.WithError(err).Error("Failed to update preferences")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update preferences"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Preferences updated"})
}

// DeleteAccount handles account deletion
// @Summary Delete account
// @Description Delete the current user's account (soft delete)
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string "Account deleted"
// @Failure 401 {string} string "Unauthorized"
// @Router /users/delete [post]
func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	if err := h.userService.DeleteUser(userID.(string)); err != nil {
		h.logger.WithError(err).Error("Failed to delete account")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Account deleted"})
}

// ListUserActivityLogs lists user activity logs (admin only)
// @Summary List user activity logs
// @Description List activity logs for a user (admin only)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param user_id query string false "User ID"
// @Param limit query int false "Limit"
// @Param offset query int false "Offset"
// @Success 200 {object} map[string]interface{} "Activity logs"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Router /admin/activity-logs [get]
func (h *UserHandler) ListUserActivityLogs(c *gin.Context) {
	userID := c.Query("user_id")
	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	logs, err := h.userService.ListUserActivityLogs(userID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list activity logs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list activity logs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs, "limit": limit, "offset": offset})
}

// BulkUpdateUsers handles batch user updates (admin only)
// @Summary Bulk update users
// @Description Batch update users (admin only)
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param updates body []models.UpdateUserRequest true "User updates"
// @Success 200 {object} map[string]interface{} "Bulk update result"
// @Failure 400 {string} string "Invalid request data"
// @Router /admin/users/bulk-update [post]
func (h *UserHandler) BulkUpdateUsers(c *gin.Context) {
	var updates []models.UpdateUserRequest
	if err := c.ShouldBindJSON(&updates); err != nil {
		h.logger.WithError(err).Error("Failed to decode bulk update request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	result, err := h.userService.BulkUpdateUsers(updates)
	if err != nil {
		h.logger.WithError(err).Error("Bulk update failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// BulkDeleteUsers handles batch user deletes (admin only)
// @Summary Bulk delete users
// @Description Batch delete users (admin only)
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param user_ids body []string true "User IDs"
// @Success 200 {object} map[string]interface{} "Bulk delete result"
// @Failure 400 {string} string "Invalid request data"
// @Router /admin/users/bulk-delete [post]
func (h *UserHandler) BulkDeleteUsers(c *gin.Context) {
	var userIDs []string
	if err := c.ShouldBindJSON(&userIDs); err != nil {
		h.logger.WithError(err).Error("Failed to decode bulk delete request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	result, err := h.userService.BulkDeleteUsers(userIDs)
	if err != nil {
		h.logger.WithError(err).Error("Bulk delete failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// Helper functions for validation
func validateChangePasswordRequest(req models.ChangePasswordRequest) error {
	if req.CurrentPassword == "" {
		return errors.New("current password is required")
	}

	if req.NewPassword == "" {
		return errors.New("new password is required")
	}

	if len(req.NewPassword) < 8 {
		return errors.New("new password must be at least 8 characters long")
	}

	return nil
}
