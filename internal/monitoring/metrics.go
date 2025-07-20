package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type Metrics struct {
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	httpRequestsInFlight *prometheus.GaugeVec
	
	dbConnectionsActive *prometheus.GaugeVec
	dbConnectionsIdle   *prometheus.GaugeVec
	dbQueryDuration     *prometheus.HistogramVec
	
	cacheHits   *prometheus.CounterVec
	cacheMisses *prometheus.CounterVec
	
	userRegistrations *prometheus.CounterVec
	userLogins        *prometheus.CounterVec
	userLogouts       *prometheus.CounterVec
	
	goroutines *prometheus.GaugeVec
	memoryUsage *prometheus.GaugeVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		httpRequestsInFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "http_requests_in_flight",
				Help: "Number of HTTP requests currently being processed",
			},
			[]string{"method", "endpoint"},
		),
		dbConnectionsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "db_connections_active",
				Help: "Number of active database connections",
			},
			[]string{"database"},
		),
		dbConnectionsIdle: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "db_connections_idle",
				Help: "Number of idle database connections",
			},
			[]string{"database"},
		),
		dbQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "db_query_duration_seconds",
				Help:    "Database query duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"database", "operation"},
		),
		cacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"cache"},
		),
		cacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"cache"},
		),
		userRegistrations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_registrations_total",
				Help: "Total number of user registrations",
			},
			[]string{"status"},
		),
		userLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_logins_total",
				Help: "Total number of user logins",
			},
			[]string{"status"},
		),
		userLogouts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_logouts_total",
				Help: "Total number of user logouts",
			},
			[]string{"status"},
		),
		goroutines: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "goroutines_total",
				Help: "Total number of goroutines",
			},
			[]string{},
		),
		memoryUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
			[]string{"type"},
		),
	}
	
	prometheus.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.httpRequestsInFlight,
		m.dbConnectionsActive,
		m.dbConnectionsIdle,
		m.dbQueryDuration,
		m.cacheHits,
		m.cacheMisses,
		m.userRegistrations,
		m.userLogins,
		m.userLogouts,
		m.goroutines,
		m.memoryUsage,
	)
	
	return m
}

func (m *Metrics) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		m.httpRequestsInFlight.WithLabelValues(c.Request.Method, c.Request.URL.Path).Inc()
		defer m.httpRequestsInFlight.WithLabelValues(c.Request.Method, c.Request.URL.Path).Dec()
		
		c.Next()
		
		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())
		
		m.httpRequestsTotal.WithLabelValues(c.Request.Method, c.Request.URL.Path, status).Inc()
		m.httpRequestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(duration)
	}
}

func (m *Metrics) RecordUserRegistration(status string) {
	m.userRegistrations.WithLabelValues(status).Inc()
}

func (m *Metrics) RecordUserLogin(status string) {
	m.userLogins.WithLabelValues(status).Inc()
}

func (m *Metrics) RecordUserLogout(status string) {
	m.userLogouts.WithLabelValues(status).Inc()
}

func (m *Metrics) RecordCacheHit(cache string) {
	m.cacheHits.WithLabelValues(cache).Inc()
}

func (m *Metrics) RecordCacheMiss(cache string) {
	m.cacheMisses.WithLabelValues(cache).Inc()
}

func (m *Metrics) RecordDBQuery(database, operation string, duration time.Duration) {
	m.dbQueryDuration.WithLabelValues(database, operation).Observe(duration.Seconds())
}

func (m *Metrics) UpdateSystemMetrics() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	
	m.goroutines.WithLabelValues().Set(float64(runtime.NumGoroutine()))
	m.memoryUsage.WithLabelValues("alloc").Set(float64(stats.Alloc))
	m.memoryUsage.WithLabelValues("sys").Set(float64(stats.Sys))
	m.memoryUsage.WithLabelValues("heap_alloc").Set(float64(stats.HeapAlloc))
	m.memoryUsage.WithLabelValues("heap_sys").Set(float64(stats.HeapSys))
}

type HealthChecker struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewHealthChecker(db *gorm.DB, redis *redis.Client) *HealthChecker {
	return &HealthChecker{
		db:    db,
		redis: redis,
	}
}

type HealthStatus struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (hc *HealthChecker) CheckHealth(ctx context.Context) map[string]HealthStatus {
	status := make(map[string]HealthStatus)
	
	status["database"] = hc.checkDatabaseHealth(ctx)
	
	status["redis"] = hc.checkRedisHealth(ctx)
	
	status["application"] = hc.checkApplicationHealth()
	
	return status
}

func (hc *HealthChecker) checkDatabaseHealth(ctx context.Context) HealthStatus {
	sqlDB, err := hc.db.DB()
	if err != nil {
		return HealthStatus{
			Status:    "unhealthy",
			Message:   "Failed to get database instance",
			Timestamp: time.Now(),
		}
	}
	
	err = sqlDB.PingContext(ctx)
	if err != nil {
		return HealthStatus{
			Status:    "unhealthy",
			Message:   "Database connection failed",
			Timestamp: time.Now(),
		}
	}
	
	stats := sqlDB.Stats()
	
	return HealthStatus{
		Status:    "healthy",
		Message:   "Database is healthy",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"open_connections": stats.OpenConnections,
			"in_use":           stats.InUse,
			"idle":             stats.Idle,
		},
	}
}

func (hc *HealthChecker) checkRedisHealth(ctx context.Context) HealthStatus {
	err := hc.redis.Ping(ctx).Err()
	if err != nil {
		return HealthStatus{
			Status:    "unhealthy",
			Message:   "Redis connection failed",
			Timestamp: time.Now(),
		}
	}
	
	info, err := hc.redis.Info(ctx).Result()
	if err != nil {
		return HealthStatus{
			Status:    "unhealthy",
			Message:   "Failed to get Redis info",
			Timestamp: time.Now(),
		}
	}
	
	return HealthStatus{
		Status:    "healthy",
		Message:   "Redis is healthy",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"info_length": len(info),
		},
	}
}

func (hc *HealthChecker) checkApplicationHealth() HealthStatus {
	return HealthStatus{
		Status:    "healthy",
		Message:   "Application is running",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"uptime":     time.Since(startTime).String(),
		},
	}
}

func SetupMonitoring(router *gin.Engine, metrics *Metrics, healthChecker *HealthChecker) {
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	router.GET("/health", func(c *gin.Context) {
		status := healthChecker.CheckHealth(c.Request.Context())
		
		allHealthy := true
		for _, s := range status {
			if s.Status != "healthy" {
				allHealthy = false
				break
			}
		}
		
		if allHealthy {
			c.JSON(http.StatusOK, gin.H{
				"status": "healthy",
				"checks": status,
			})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"checks": status,
			})
		}
	})
	
	router.GET("/ready", func(c *gin.Context) {
		status := healthChecker.CheckHealth(c.Request.Context())
		
		dbHealthy := status["database"].Status == "healthy"
		redisHealthy := status["redis"].Status == "healthy"
		
		if dbHealthy && redisHealthy {
			c.JSON(http.StatusOK, gin.H{"status": "ready"})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
		}
	})
	
	router.GET("/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})
}

var startTime = time.Now() 
