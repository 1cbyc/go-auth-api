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

// ListUsers retrieves a list of users (admin only)
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
