package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Cache represents a Redis-based cache
type Cache struct {
	client *redis.Client
}

// NewCache creates a new cache instance
func NewCache(client *redis.Client) *Cache {
	return &Cache{
		client: client,
	}
}

// Set stores a value in cache with TTL
func (c *Cache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.Set(ctx, key, data, ttl).Err()
}

// Get retrieves a value from cache
func (c *Cache) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return ErrKeyNotFound
		}
		return fmt.Errorf("failed to get key: %w", err)
	}

	return json.Unmarshal(data, dest)
}

// Delete removes a key from cache
func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

// DeletePattern removes keys matching a pattern
func (c *Cache) DeletePattern(ctx context.Context, pattern string) error {
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys: %w", err)
	}

	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}

	return nil
}

// Exists checks if a key exists
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	result, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	return result > 0, nil
}

// TTL gets the remaining TTL for a key
func (c *Cache) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, key).Result()
}

// SetNX sets a value only if the key doesn't exist
func (c *Cache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.SetNX(ctx, key, data, ttl).Result()
}

// Increment increments a numeric value
func (c *Cache) Increment(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, key).Result()
}

// IncrementBy increments a numeric value by a specific amount
func (c *Cache) IncrementBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.client.IncrBy(ctx, key, value).Result()
}

// HashSet sets a field in a hash
func (c *Cache) HashSet(ctx context.Context, key string, field string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.HSet(ctx, key, field, data).Err()
}

// HashGet gets a field from a hash
func (c *Cache) HashGet(ctx context.Context, key string, field string, dest interface{}) error {
	data, err := c.client.HGet(ctx, key, field).Bytes()
	if err != nil {
		if err == redis.Nil {
			return ErrKeyNotFound
		}
		return fmt.Errorf("failed to get hash field: %w", err)
	}

	return json.Unmarshal(data, dest)
}

// HashGetAll gets all fields from a hash
func (c *Cache) HashGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.client.HGetAll(ctx, key).Result()
}

// ListPush pushes a value to a list
func (c *Cache) ListPush(ctx context.Context, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.LPush(ctx, key, data).Err()
}

// ListPop pops a value from a list
func (c *Cache) ListPop(ctx context.Context, key string, dest interface{}) error {
	data, err := c.client.LPop(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return ErrKeyNotFound
		}
		return fmt.Errorf("failed to pop from list: %w", err)
	}

	return json.Unmarshal(data, dest)
}

// ListRange gets a range of values from a list
func (c *Cache) ListRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return c.client.LRange(ctx, key, start, stop).Result()
}

// CacheWarmer represents a cache warming utility
type CacheWarmer struct {
	cache *Cache
}

// NewCacheWarmer creates a new cache warmer
func NewCacheWarmer(cache *Cache) *CacheWarmer {
	return &CacheWarmer{
		cache: cache,
	}
}

// WarmCache warms the cache with data from a data source
func (cw *CacheWarmer) WarmCache(ctx context.Context, keys []string, dataSource func(key string) (interface{}, error), ttl time.Duration) error {
	for _, key := range keys {
		data, err := dataSource(key)
		if err != nil {
			continue // Skip failed items
		}

		err = cw.cache.Set(ctx, key, data, ttl)
		if err != nil {
			continue // Skip failed cache sets
		}
	}

	return nil
}

// CacheStats represents cache statistics
type CacheStats struct {
	HitCount   int64
	MissCount  int64
	TotalCount int64
}

// GetStats gets cache statistics
func (c *Cache) GetStats(ctx context.Context) (*CacheStats, error) {
	// This is a simplified implementation
	// In a real scenario, you'd track hits/misses in application code
	stats := &CacheStats{}

	// Get total keys
	keys, err := c.client.Keys(ctx, "*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}

	stats.TotalCount = int64(len(keys))

	return stats, nil
}

// CacheMiddleware provides caching middleware for HTTP handlers
func (c *Cache) CacheMiddleware(ttl time.Duration) func(gin.HandlerFunc) gin.HandlerFunc {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			// Generate cache key from request
			cacheKey := fmt.Sprintf("http:%s:%s", ctx.Request.Method, ctx.Request.URL.Path)

			// Try to get from cache
			var cachedResponse map[string]interface{}
			err := c.Get(ctx.Request.Context(), cacheKey, &cachedResponse)
			if err == nil {
				// Return cached response
				ctx.JSON(200, cachedResponse)
				return
			}

			// Continue to handler
			next(ctx)

			// Cache the response if it's successful
			if ctx.Writer.Status() == 200 {
				// Note: This is a simplified implementation
				// In a real scenario, you'd capture the response body
			}
		}
	}
}

// Errors
var (
	ErrKeyNotFound = fmt.Errorf("key not found in cache")
)
