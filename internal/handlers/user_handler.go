package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/1cbyc/go-auth-api/internal/middleware"
	"github.com/1cbyc/go-auth-api/internal/models"
	"github.com/1cbyc/go-auth-api/internal/services"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	userService *services.UserService
	logger      *logrus.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *services.UserService, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
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
func (h *UserHandler) GetProfile() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user, ok := middleware.GetUserFromContext(r.Context())
		if !ok {
			h.logger.Error("User not found in context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user profile
		profile, err := h.userService.GetProfile(user.ID)
		if err != nil {
			h.logger.WithError(err).Error("Failed to get user profile")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(profile)
	})
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
func (h *UserHandler) UpdateProfile() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user, ok := middleware.GetUserFromContext(r.Context())
		if !ok {
			h.logger.Error("User not found in context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req models.UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode update profile request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Update user profile
		updatedUser, err := h.userService.UpdateProfile(user.ID, req)
		if err != nil {
			h.logger.WithError(err).Error("Failed to update user profile")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(updatedUser)
	})
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
func (h *UserHandler) ChangePassword() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user, ok := middleware.GetUserFromContext(r.Context())
		if !ok {
			h.logger.Error("User not found in context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req models.ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode change password request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate request
		if err := validateChangePasswordRequest(req); err != nil {
			h.logger.WithError(err).Error("Invalid change password request")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Change password
		if err := h.userService.ChangePassword(user.ID, req); err != nil {
			h.logger.WithError(err).Error("Failed to change password")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password changed successfully",
		})
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
func (h *UserHandler) ListUsers() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"users":  users,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	})
}

// GetUser retrieves a specific user by ID (admin only)
// @Summary Get user by ID
// @Description Get a specific user by their ID (admin only)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.User "User retrieved successfully"
// @Failure 400 {string} string "Invalid user ID"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - Admin role required"
// @Failure 404 {string} string "User not found"
// @Router /admin/users/{id} [get]
func (h *UserHandler) GetUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from URL parameters
		vars := mux.Vars(r)
		userID := vars["id"]

		if userID == "" {
			h.logger.Error("User ID is required")
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		// Get user
		user, err := h.userService.GetUser(userID)
		if err != nil {
			h.logger.WithError(err).Error("Failed to get user")
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	})
}

// UpdateUser updates a specific user by ID (admin only)
// @Summary Update user by ID
// @Description Update a specific user by their ID (admin only)
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
func (h *UserHandler) UpdateUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from URL parameters
		vars := mux.Vars(r)
		userID := vars["id"]

		if userID == "" {
			h.logger.Error("User ID is required")
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req models.UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.WithError(err).Error("Failed to decode update user request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Update user
		updatedUser, err := h.userService.UpdateUser(userID, req)
		if err != nil {
			h.logger.WithError(err).Error("Failed to update user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(updatedUser)
	})
}

// DeleteUser deletes a specific user by ID (admin only)
// @Summary Delete user by ID
// @Description Delete a specific user by their ID (admin only)
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
func (h *UserHandler) DeleteUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from URL parameters
		vars := mux.Vars(r)
		userID := vars["id"]

		if userID == "" {
			h.logger.Error("User ID is required")
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		// Delete user
		if err := h.userService.DeleteUser(userID); err != nil {
			h.logger.WithError(err).Error("Failed to delete user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User deleted successfully",
		})
	})
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
