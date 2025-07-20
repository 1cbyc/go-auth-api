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

	_ "go-auth-api/docs"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	cfg := config.Load()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	logConfig := logging.DefaultLogConfig()
	logConfig.Development = cfg.Environment == "development"
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	db, err := database.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", err)
	}

	userRepo := database.NewGORMUserRepository(db)
	refreshTokenRepo := database.NewGORMRefreshTokenRepository(db)
	passwordResetRepo := database.NewGORMPasswordResetTokenRepository(db)
	emailVerificationRepo := database.NewGORMEmailVerificationTokenRepository(db)
	userActivityRepo := database.NewGORMUserActivityRepository(db)

	authService := services.NewAuthService(userRepo, refreshTokenRepo, passwordResetRepo, emailVerificationRepo, cfg.JWT)
	userService := services.NewUserService(userRepo, userActivityRepo, cfg)

	cacheService := cache.NewCache(redisClient)

	metrics := monitoring.NewMetrics()
	healthChecker := monitoring.NewHealthChecker(db, redisClient)

	securityConfig := security.DefaultSecurityConfig()
	inputValidator := security.NewInputValidator()

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
			Provider:  "twilio",
			APIKey:    cfg.SMS.APIKey,
			APISecret: cfg.SMS.APISecret,
			From:      cfg.SMS.From,
		},
		Push: notification.PushConfig{
			Provider:  "firebase",
			APIKey:    cfg.Push.APIKey,
			APISecret: cfg.Push.APISecret,
		},
	}
	notificationService := notification.NewNotificationService(notificationConfig)

	jobQueue := queue.NewJobQueue(redisClient)
	defaultQueue := jobQueue.NewQueue("default")
	jobProcessor := queue.NewJobProcessor(defaultQueue, 5)

	jobProcessor.RegisterHandler("email", func(ctx context.Context, job *queue.Job) error {
		return nil
	})
	jobProcessor.RegisterHandler("sms", func(ctx context.Context, job *queue.Job) error {
		return nil
	})

	jobProcessor.Start(ctx)

	wsHub := websocket.NewHub()
	go wsHub.Run(ctx)

	authHandler := handlers.NewAuthHandler(authService, userService, notificationService, jobQueue, logger)
	userHandler := handlers.NewUserHandler(userService, cacheService, logger)
	notificationHandler := notification.NewNotificationHandler(notificationService)
	wsHandler := websocket.NewWebSocketHandler(wsHub)
	jobQueueHandler := queue.NewJobQueueHandler(jobQueue)

	apiGateway := gateway.NewGateway()
	apiGateway.AddRoute(gateway.Route{
		Path:        "/api/v1/external",
		Target:      "http://external-service:8080",
		Method:      "GET",
		StripPrefix: true,
		Timeout:     30 * time.Second,
	})

	router := gin.New()

	router.Use(security.SecurityMiddleware(securityConfig))
	router.Use(security.XSSProtectionMiddleware())
	router.Use(security.SQLInjectionProtectionMiddleware())
	router.Use(security.TrustedProxyMiddleware(securityConfig.TrustedProxies))

	router.Use(logger.LoggingMiddleware())

	router.Use(metrics.MetricsMiddleware())

	router.Use(middleware.RateLimiter(redisClient))

	router.Use(middleware.CORSMiddleware(cfg.CORS))

	router.Use(middleware.RequestIDMiddleware())

	monitoring.SetupMonitoring(router, metrics, healthChecker)

	apiGateway.SetupRoutes(router)

	api := router.Group("/api/v1")
	{
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

		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		admin.Use(middleware.RoleMiddleware("admin"))
		{
			admin.GET("/users", userHandler.GetAllUsers)
			admin.PUT("/users/bulk", userHandler.BulkUpdateUsers)
			admin.DELETE("/users/bulk", userHandler.BulkDeleteUsers)
			admin.POST("/users/:user_id/unlock", userHandler.UnlockAccount)
		}

		notifications := api.Group("/notifications")
		notifications.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		{
			notifications.POST("/send", notificationHandler.SendNotification)
			notifications.GET("/status/:id", notificationHandler.GetNotificationStatus)
		}

		ws := api.Group("/ws")
		ws.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		{
			ws.GET("/connect", wsHandler.HandleWebSocket)
			ws.GET("/stats", wsHandler.GetConnectionCount)
			ws.GET("/rooms/:room_id", wsHandler.GetRoomInfo)
			ws.POST("/broadcast", wsHandler.BroadcastMessage)
		}

		queue := api.Group("/queue")
		queue.Use(middleware.AuthMiddleware(cfg.JWT.Secret))
		queue.Use(middleware.RoleMiddleware("admin"))
		{
			queue.POST("/:queue/enqueue", jobQueueHandler.EnqueueJob)
			queue.GET("/:queue/jobs/:job_id", jobQueueHandler.GetJobStatus)
			queue.GET("/:queue/stats", jobQueueHandler.GetQueueStats)
		}
	}

	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jobProcessor.Stop()

	if err := redisClient.Close(); err != nil {
		logger.Error("Error closing Redis connection", err)
	}

	sqlDB, err := db.DB()
	if err == nil {
		if err := sqlDB.Close(); err != nil {
			logger.Error("Error closing database connection", err)
		}
	}

	logger.Info("Server stopped")
}
