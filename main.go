package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1cbyc/go-auth-api/internal/config"
	"github.com/1cbyc/go-auth-api/internal/handlers"
	"github.com/1cbyc/go-auth-api/internal/middleware"
	"github.com/1cbyc/go-auth-api/internal/repository"
	"github.com/1cbyc/go-auth-api/internal/services"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging
	setupLogging(cfg)

	logger.Info("Starting Go Auth API Server...")

	// Initialize repositories
	userRepo := repository.NewInMemoryUserRepository()
	
	// Initialize services
	authService := services.NewAuthService(userRepo, cfg)
	userService := services.NewUserService(userRepo)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	healthHandler := handlers.NewHealthHandler()

	// Setup router
	router := setupRouter(authHandler, userHandler, healthHandler, cfg)

	// Setup CORS
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   cfg.CORS.AllowedOrigins,
		AllowedMethods:   cfg.CORS.AllowedMethods,
		AllowedHeaders:   cfg.CORS.AllowedHeaders,
		AllowCredentials: true,
		MaxAge:           int(cfg.CORS.MaxAge.Seconds()),
	})

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      corsMiddleware.Handler(router),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Server listening on port %d", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}

func setupLogging(cfg *config.Config) {
	level, err := logrus.ParseLevel(cfg.Log.Level)
	if err != nil {
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logger.SetLevel(level)
	}

	if cfg.Log.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}
}

func setupRouter(authHandler *handlers.AuthHandler, userHandler *handlers.UserHandler, healthHandler *handlers.HealthHandler, cfg *config.Config) *mux.Router {
	router := mux.NewRouter()

	// Middleware chain
	commonMiddleware := alice.New(
		middleware.RequestLogger(logger),
		middleware.Recovery(logger),
		middleware.RequestID,
	)

	// Health check (no auth required)
	router.Handle("/health", commonMiddleware.Then(healthHandler)).Methods("GET")

	// Auth routes (no auth required)
	authRoutes := router.PathPrefix("/api/v1/auth").Subrouter()
	authRoutes.Handle("/register", commonMiddleware.Then(authHandler.Register())).Methods("POST")
	authRoutes.Handle("/login", commonMiddleware.Then(authHandler.Login())).Methods("POST")
	authRoutes.Handle("/refresh", commonMiddleware.Then(authHandler.RefreshToken())).Methods("POST")
	authRoutes.Handle("/logout", commonMiddleware.Then(authHandler.Logout())).Methods("POST")

	// Protected routes
	protectedMiddleware := alice.New(
		middleware.RequestLogger(logger),
		middleware.Recovery(logger),
		middleware.RequestID,
		middleware.AuthMiddleware(cfg.JWT.Secret),
	)

	// User routes (authenticated)
	userRoutes := router.PathPrefix("/api/v1/users").Subrouter()
	userRoutes.Handle("/profile", protectedMiddleware.Then(userHandler.GetProfile())).Methods("GET")
	userRoutes.Handle("/profile", protectedMiddleware.Then(userHandler.UpdateProfile())).Methods("PUT")
	userRoutes.Handle("/change-password", protectedMiddleware.Then(userHandler.ChangePassword())).Methods("POST")

	// Admin routes (admin role required)
	adminMiddleware := alice.New(
		middleware.RequestLogger(logger),
		middleware.Recovery(logger),
		middleware.RequestID,
		middleware.AuthMiddleware(cfg.JWT.Secret),
		middleware.RoleMiddleware("admin"),
	)

	adminRoutes := router.PathPrefix("/api/v1/admin").Subrouter()
	adminRoutes.Handle("/users", adminMiddleware.Then(userHandler.ListUsers())).Methods("GET")
	adminRoutes.Handle("/users/{id}", adminMiddleware.Then(userHandler.GetUser())).Methods("GET")
	adminRoutes.Handle("/users/{id}", adminMiddleware.Then(userHandler.UpdateUser())).Methods("PUT")
	adminRoutes.Handle("/users/{id}", adminMiddleware.Then(userHandler.DeleteUser())).Methods("DELETE")

	// API documentation
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	}).Methods("GET")

	return router
}
