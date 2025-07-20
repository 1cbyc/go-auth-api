package handlers

import (
	"net/http"
	"time"

	"go-auth-api/internal/database"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	db *database.Database
}

func NewHealthHandler(db *database.Database) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "go-auth-api",
		"version":   "1.0.0",
	}

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
