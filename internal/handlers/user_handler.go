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

type UserHandler struct {
	userService *services.UserService
	logger      *logrus.Logger
	storage     *storage.Storage // added for file storage
}

func NewUserHandler(userService *services.UserService, logger *logrus.Logger, storage *storage.Storage) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
		storage:     storage, // added
	}
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	profile, err := h.userService.GetProfile(userID.(string))
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user profile")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, profile)
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update profile request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	updatedUser, err := h.userService.UpdateProfile(userID.(string), req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user profile")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updatedUser)
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode change password request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := validateChangePasswordRequest(req); err != nil {
		h.logger.WithError(err).Error("Invalid change password request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ChangePassword(userID.(string), req); err != nil {
		h.logger.WithError(err).Error("Failed to change password")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

func (h *UserHandler) ListUsers(c *gin.Context) {
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

	users, total, err := h.userService.ListUsers(limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	user, err := h.userService.GetUser(userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user")
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update user request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	updatedUser, err := h.userService.UpdateProfile(userID, req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updatedUser)
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	if err := h.userService.DeleteUser(userID); err != nil {
		h.logger.WithError(err).Error("Failed to delete user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

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
