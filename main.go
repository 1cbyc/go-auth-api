package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-auth-api/internal/cache"
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/gateway"
	"go-auth-api/internal/handlers"
	"go-auth-api/internal/logging"
	"go-auth-api/internal/middleware"
	"go-auth-api/internal/monitoring"
	"go-auth-api/internal/notification"
	"go-auth-api/internal/queue"
	"go-auth-api/internal/security"
	"go-auth-api/internal/services"
	"go-auth-api/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/swaggo/gin-swagger"
	"github.com/swaggo/files"
	_ "go-auth-api/docs"
)

// @title Go Auth API
// @version 1.0
// @description A sophisticated authentication and authorization API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize logger
	logConfig := logging.DefaultLogConfig()
	logConfig.Development = cfg.Environment == "development"
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Initialize database
	db, err := database.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", err)
	}

	// Initialize repositories
	userRepo := database.NewGORMUserRepository(db)
	refreshTokenRepo := database.NewGORMRefreshTokenRepository(db)
	passwordResetRepo := database.NewGORMPasswordResetTokenRepository(db)
	emailVerificationRepo := database.NewGORMEmailVerificationTokenRepository(db)
	userActivityRepo := database.NewGORMUserActivityRepository(db)

	// Initialize services
	authService := services.NewAuthService(userRepo, refreshTokenRepo, passwordResetRepo, emailVerificationRepo, cfg.JWT)
	userService := services.NewUserService(userRepo, userActivityRepo, cfg)

	// Initialize cache
	cacheService := cache.NewCache(redisClient)

	// Initialize monitoring
	metrics := monitoring.NewMetrics()
	healthChecker := monitoring.NewHealthChecker(db, redisClient)

	// Initialize security
	securityConfig := security.DefaultSecurityConfig()
	inputValidator := security.NewInputValidator()

	// Initialize notification service
	notificationConfig := notification.NotificationConfig{
		Email: notification.EmailConfig{
			SMTPHost:     cfg.Email.SMTPHost,
			SMTPPort:     cfg.Email.SMTPPort,
			SMTPUsername: cfg.Email.SMTPUsername,
			SMTPPassword: cfg.Email.SMTPPassword,
			FromEmail:    cfg.Email.FromEmail,
			FromName:     cfg.Email.FromName,
		},
		SMS: notification.SMSConfig{
			Provider:  "twilio", // Example
			APIKey:    cfg.SMS.APIKey,
			APISecret: cfg.SMS.APISecret,
			From:      cfg.SMS.From,
		},
		Push: notification.PushConfig{
			Provider:  "firebase", // Example
			APIKey:    cfg.Push.APIKey,
			APISecret: cfg.Push.APISecret,
		},
	}
	notificationService := notification.NewNotificationService(notificationConfig)

	// Initialize job queue
	jobQueue := queue.NewJobQueue(redisClient)
	defaultQueue := jobQueue.NewQueue("default")
	jobProcessor := queue.NewJobProcessor(defaultQueue, 5)

	// Register job handlers
	jobProcessor.RegisterHandler("email", func(ctx context.Context, job *queue.Job) error {
		// Handle email job
		return nil
	})
	jobProcessor.RegisterHandler("sms", func(ctx context.Context, job *queue.Job) error {
		// Handle SMS job
		return nil
	})

	// Start job processor
	jobProcessor.Start(ctx)

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	go wsHub.Run(ctx)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, userService, notificationService, jobQueue, logger)
	userHandler := handlers.NewUserHandler(userService, cacheService, logger)
	notificationHandler := notification.NewNotificationHandler(notificationService)
	wsHandler := websocket.NewWebSocketHandler(wsHub)
	jobQueueHandler := queue.NewJobQueueHandler(jobQueue)

	// Initialize API gateway
	apiGateway := gateway.NewGateway()
	apiGateway.AddRoute(gateway.Route{
		Path:        "/api/v1/external",
		Target:      "http://external-service:8080",
		Method:      "GET",
		StripPrefix: true,
		Timeout:     30 * time.Second,
	})

	// Set up Gin router
	router := gin.New()

	// Security middleware
	router.Use(security.SecurityMiddleware(securityConfig))
	router.Use(security.XSSProtectionMiddleware())
	router.Use(security.SQLInjectionProtectionMiddleware())
	router.Use(security.TrustedProxyMiddleware(securityConfig.TrustedProxies))

	// Logging middleware
	router.Use(logger.LoggingMiddleware())

	// Metrics middleware
	router.Use(metrics.MetricsMiddleware())

	// Rate limiting middleware
	router.Use(middleware.RateLimiter(redisClient))

	// CORS middleware
	router.Use(middleware.CORSMiddleware(cfg.CORS))

	// Request ID middleware
	router.Use(middleware.RequestIDMiddleware())

	// Setup monitoring endpoints
	monitoring.SetupMonitoring(router, metrics, healthChecker)

	// Setup API gateway routes
	apiGateway.SetupRoutes(router)

	// API routes
	api := router.Group("/api/v1")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.POST("/logout", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.Logout)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
			auth.POST("/verify-email", authHandler.VerifyEmail)
			auth.POST("/resend-verification", authHandler.ResendVerification)
			auth.POST("/2fa/setup", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.Setup2FA)
			auth.POST("/2fa/verify", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.Verify2FA)
			auth.POST("/2fa/disable", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.Disable2FA)
			auth.GET("/google", authHandler.GoogleLogin)
			auth.GET("/google/callback", authHandler.GoogleCallback)
			auth.GET("/sessions", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.GetSessions)
			auth.DELETE("/sessions/:session_id", middleware.AuthMiddleware(cfg.JWT.Secret), authHandler.RevokeSession)
		}

		// User routes
		users := api.Group("/users")
		users.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		{
			users.GET("/profile", userHandler.GetProfile)
			users.PUT("/profile", userHandler.UpdateProfile)
			users.POST("/avatar", userHandler.UploadAvatar)
			users.GET("/avatar/:user_id", userHandler.GetAvatar)
			users.GET("/preferences", userHandler.GetPreferences)
			users.PUT("/preferences", userHandler.UpdatePreferences)
			users.DELETE("/account", userHandler.DeleteAccount)
			users.GET("/activity", userHandler.GetActivityLog)
		}

		// Admin routes
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		admin.Use(middleware.RoleMiddleware("admin"))
		{
			admin.GET("/users", userHandler.GetAllUsers)
			admin.PUT("/users/bulk", userHandler.BulkUpdateUsers)
			admin.DELETE("/users/bulk", userHandler.BulkDeleteUsers)
			admin.POST("/users/:user_id/unlock", userHandler.UnlockAccount)
		}

		// Notification routes
		notifications := api.Group("/notifications")
		notifications.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		{
			notifications.POST("/send", notificationHandler.SendNotification)
			notifications.GET("/status/:id", notificationHandler.GetNotificationStatus)
		}

		// WebSocket routes
		ws := api.Group("/ws")
		ws.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		{
			ws.GET("/connect", wsHandler.HandleWebSocket)
			ws.GET("/stats", wsHandler.GetConnectionCount)
			ws.GET("/rooms/:room_id", wsHandler.GetRoomInfo)
			ws.POST("/broadcast", wsHandler.BroadcastMessage)
		}

		// Job queue routes
		queue := api.Group("/queue")
		queue.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		queue.Use(middleware.RoleMiddleware("admin"))
		{
			queue.POST("/:queue/enqueue", jobQueueHandler.EnqueueJob)
			queue.GET("/:queue/jobs/:job_id", jobQueueHandler.GetJobStatus)
			queue.GET("/:queue/stats", jobQueueHandler.GetQueueStats)
		}
	}

	// Swagger documentation
	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := router.Run(cfg.Server.Address); err != nil {
			logger.Fatal("Failed to start server", err)
		}
	}()

	logger.Info("Server started", "address", cfg.Server.Address)

	<-quit
	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop job processor
	jobProcessor.Stop()

	// Close Redis connection
	if err := redisClient.Close(); err != nil {
		logger.Error("Error closing Redis connection", err)
	}

	// Close database connection
	sqlDB, err := db.DB()
	if err == nil {
		if err := sqlDB.Close(); err != nil {
			logger.Error("Error closing database connection", err)
		}
	}

	logger.Info("Server stopped")
}
