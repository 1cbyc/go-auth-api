package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Cache struct {
	client *redis.Client
}

func NewCache(client *redis.Client) *Cache {
	return &Cache{
		client: client,
	}
}

func (c *Cache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.Set(ctx, key, data, ttl).Err()
}

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

func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

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

func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	result, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	return result > 0, nil
}

func (c *Cache) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, key).Result()
}

func (c *Cache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.SetNX(ctx, key, data, ttl).Result()
}

func (c *Cache) Increment(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, key).Result()
}

func (c *Cache) IncrementBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.client.IncrBy(ctx, key, value).Result()
}

func (c *Cache) HashSet(ctx context.Context, key string, field string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.HSet(ctx, key, field, data).Err()
}

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

func (c *Cache) HashGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.client.HGetAll(ctx, key).Result()
}

func (c *Cache) ListPush(ctx context.Context, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.client.LPush(ctx, key, data).Err()
}

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

func (c *Cache) ListRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return c.client.LRange(ctx, key, start, stop).Result()
}

type CacheWarmer struct {
	cache *Cache
}

func NewCacheWarmer(cache *Cache) *CacheWarmer {
	return &CacheWarmer{
		cache: cache,
	}
}

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

type CacheStats struct {
	HitCount   int64
	MissCount  int64
	TotalCount int64
}

func (c *Cache) GetStats(ctx context.Context) (*CacheStats, error) {
	stats := &CacheStats{}

	keys, err := c.client.Keys(ctx, "*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}

	stats.TotalCount = int64(len(keys))

	return stats, nil
}

func (c *Cache) CacheMiddleware(ttl time.Duration) func(gin.HandlerFunc) gin.HandlerFunc {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			cacheKey := fmt.Sprintf("http:%s:%s", ctx.Request.Method, ctx.Request.URL.Path)

			var cachedResponse map[string]interface{}
			err := c.Get(ctx.Request.Context(), cacheKey, &cachedResponse)
			if err == nil {
				ctx.JSON(200, cachedResponse)
				return
			}

			next(ctx)

			if ctx.Writer.Status() == 200 {
			}
		}
	}
}

var (
	ErrKeyNotFound = fmt.Errorf("key not found in cache")
)
