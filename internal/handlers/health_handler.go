package handlers

import (
	"net/http"
	"time"

	"go-auth-api/internal/database"

	"github.com/gin-gonic/gin"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	db *database.Database
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *database.Database) *HealthHandler {
	return &HealthHandler{db: db}
}

// HealthCheck handles health check requests
// @Summary Health check
// @Description Check the health status of the API and database
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{} "API is healthy"
// @Router /health [get]
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "go-auth-api",
		"version":   "1.0.0",
	}

	// Check database health
	if h.db != nil {
		if err := h.db.HealthCheck(); err != nil {
			health["status"] = "unhealthy"
			health["database"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			c.JSON(http.StatusServiceUnavailable, health)
			return
		}
		health["database"] = map[string]interface{}{
			"status": "healthy",
		}
	}

	c.JSON(http.StatusOK, health)
}
