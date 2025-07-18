package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/1cbyc/go-auth-api/internal/models"
	"github.com/1cbyc/go-auth-api/internal/services"
)

// ContextKey represents a context key type
type ContextKey string

const (
	// UserContextKey is the key used to store user in context
	UserContextKey ContextKey = "user"
)

// AuthMiddleware validates JWT tokens and adds user to request context
func AuthMiddleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check if it's a Bearer token
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := tokenParts[1]

			// Create a temporary auth service to validate token
			// In a real application, you might want to inject this as a dependency
			authService := &services.AuthService{}

			// Validate token
			user, err := authService.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Add user to request context
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RoleMiddleware checks if the authenticated user has the required role
func RoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context
			user, ok := r.Context().Value(UserContextKey).(*models.User)
			if !ok {
				http.Error(w, "User not found in context", http.StatusInternalServerError)
				return
			}

			// Check if user has the required role
			if !user.HasRole(requiredRole) {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext retrieves the user from the request context
func GetUserFromContext(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value(UserContextKey).(*models.User)
	return user, ok
}
