package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimiterConfig holds rate limiting configuration
type RateLimiterConfig struct {
	RequestsPerMinute int
	RequestsPerHour   int
	BurstSize         int
	WindowSize        time.Duration
}

// Default rate limits for different endpoints
var DefaultRateLimits = map[string]RateLimiterConfig{
	"auth": {
		RequestsPerMinute: 5,
		RequestsPerHour:   100,
		BurstSize:         10,
		WindowSize:        time.Minute,
	},
	"api": {
		RequestsPerMinute: 60,
		RequestsPerHour:   1000,
		BurstSize:         100,
		WindowSize:        time.Minute,
	},
	"upload": {
		RequestsPerMinute: 10,
		RequestsPerHour:   100,
		BurstSize:         5,
		WindowSize:        time.Minute,
	},
}

// RateLimiter middleware for distributed rate limiting
func RateLimiter(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client identifier (IP or user ID)
		clientID := getClientIdentifier(c)
		
		// Determine rate limit config based on endpoint
		config := getRateLimitConfig(c.Request.URL.Path)
		
		// Check rate limit
		allowed, remaining, resetTime, err := checkRateLimit(c.Request.Context(), redisClient, clientID, config)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit check failed"})
			c.Abort()
			return
		}
		
		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.RequestsPerMinute))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
		
		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"retry_after": resetTime - time.Now().Unix(),
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// getClientIdentifier returns a unique identifier for the client
func getClientIdentifier(c *gin.Context) string {
	// Try to get user ID from context first
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%v", userID)
	}
	
	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// getRateLimitConfig returns the appropriate rate limit config for the endpoint
func getRateLimitConfig(path string) RateLimiterConfig {
	if contains(path, "/auth/") {
		return DefaultRateLimits["auth"]
	}
	if contains(path, "/upload") || contains(path, "/avatar") {
		return DefaultRateLimits["upload"]
	}
	return DefaultRateLimits["api"]
}

// checkRateLimit checks if the request is within rate limits
func checkRateLimit(ctx context.Context, redisClient *redis.Client, clientID string, config RateLimiterConfig) (bool, int, int64, error) {
	now := time.Now()
	windowStart := now.Truncate(config.WindowSize)
	key := fmt.Sprintf("rate_limit:%s:%d", clientID, windowStart.Unix())
	
	// Get current count
	count, err := redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return false, 0, 0, err
	}
	
	// Check if limit exceeded
	limit := config.RequestsPerMinute
	if count >= limit {
		// Calculate reset time
		resetTime := windowStart.Add(config.WindowSize).Unix()
		return false, 0, resetTime, nil
	}
	
	// Increment counter
	pipe := redisClient.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, config.WindowSize)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, 0, err
	}
	
	remaining := limit - count - 1
	resetTime := windowStart.Add(config.WindowSize).Unix()
	
	return true, remaining, resetTime, nil
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
} 