package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestIDKey is the context key for request ID
const RequestIDKey = "request_id"

// RequestLogger logs HTTP requests
func RequestLogger(logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Get request ID from context
			requestID := r.Context().Value(RequestIDKey)
			if requestID == nil {
				requestID = "unknown"
			}

			// Create a custom response writer to capture status code
			responseWriter := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(responseWriter, r)

			// Calculate duration
			duration := time.Since(start)

			// Log request details
			logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"method":     r.Method,
				"path":       r.URL.Path,
				"status":     responseWriter.statusCode,
				"duration":   duration,
				"user_agent": r.UserAgent(),
				"remote_ip":  r.RemoteAddr,
			}).Info("HTTP request processed")
		})
	}
}

// Recovery handles panics and logs them
func Recovery(logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Get request ID from context
					requestID := r.Context().Value(RequestIDKey)
					if requestID == nil {
						requestID = "unknown"
					}

					logger.WithFields(logrus.Fields{
						"request_id": requestID,
						"method":     r.Method,
						"path":       r.URL.Path,
						"error":      err,
					}).Error("Panic recovered")

					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// RequestID adds a unique request ID to each request
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate request ID
		requestID := uuid.New().String()

		// Add request ID to context
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)

		// Add request ID to response headers
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// responseWriter is a custom response writer that captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.ResponseWriter.Write(b)
}
