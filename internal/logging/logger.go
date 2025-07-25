package logging

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	zap *zap.Logger
}

func NewLogger(config LogConfig) (*Logger, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	var core zapcore.Core

	if config.Development {
		core = zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			config.Level,
		)
	} else {
		writer := &lumberjack.Logger{
			Filename:   config.LogFile,
			MaxSize:    config.MaxSize, // MB
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge, // days
			Compress:   config.Compress,
		}

		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(writer),
			config.Level,
		)
	}

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{zap: zapLogger}, nil
}

type LogConfig struct {
	Development bool
	Level       zapcore.Level
	LogFile     string
	MaxSize     int
	MaxBackups  int
	MaxAge      int
	Compress    bool
}

func DefaultLogConfig() LogConfig {
	return LogConfig{
		Development: false,
		Level:       zapcore.InfoLevel,
		LogFile:     "logs/app.log",
		MaxSize:     100, // MB
		MaxBackups:  3,
		MaxAge:      28, // days
		Compress:    true,
	}
}

func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.zap.Info(msg, fields...)
}

func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.zap.Error(msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.zap.Warn(msg, fields...)
}

func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.zap.Debug(msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.zap.Fatal(msg, fields...)
}

func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := []zap.Field{}

	if requestID := ctx.Value("request_id"); requestID != nil {
		fields = append(fields, zap.String("request_id", fmt.Sprintf("%v", requestID)))
	}

	if userID := ctx.Value("user_id"); userID != nil {
		fields = append(fields, zap.String("user_id", fmt.Sprintf("%v", userID)))
	}

	return &Logger{zap: l.zap.With(fields...)}
}

func (l *Logger) WithFields(fields ...zap.Field) *Logger {
	return &Logger{zap: l.zap.With(fields...)}
}

func (l *Logger) Sync() error {
	return l.zap.Sync()
}

func (l *Logger) LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		logger := l.WithContext(c.Request.Context())

		logger.Info("HTTP Request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("remote_addr", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)

		c.Next()

		duration := time.Since(start)
		logger.Info("HTTP Response",
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", duration),
			zap.Int("size", c.Writer.Size()),
		)

		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				logger.Error("HTTP Error",
					zap.Error(err.Err),
					zap.String("type", err.Type.String()),
				)
			}
		}
	}
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

type AuditLogger struct {
	logger *Logger
}

func NewAuditLogger(logger *Logger) *AuditLogger {
	return &AuditLogger{logger: logger}
}

type AuditEvent struct {
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Details   map[string]interface{} `json:"details,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

func (al *AuditLogger) LogEvent(ctx context.Context, event AuditEvent) {
	logger := al.logger.WithContext(ctx)

	fields := []zap.Field{
		zap.String("audit_user_id", event.UserID),
		zap.String("audit_action", event.Action),
		zap.String("audit_resource", event.Resource),
		zap.Time("audit_timestamp", event.Timestamp),
	}

	if event.IPAddress != "" {
		fields = append(fields, zap.String("audit_ip_address", event.IPAddress))
	}

	if event.UserAgent != "" {
		fields = append(fields, zap.String("audit_user_agent", event.UserAgent))
	}

	if len(event.Details) > 0 {
		fields = append(fields, zap.Any("audit_details", event.Details))
	}

	logger.Info("Audit Event", fields...)
}

func (al *AuditLogger) LogUserLogin(ctx context.Context, userID, ipAddress, userAgent string, success bool) {
	event := AuditEvent{
		UserID:    userID,
		Action:    "login",
		Resource:  "user",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"success": success,
		},
	}

	al.LogEvent(ctx, event)
}

func (al *AuditLogger) LogUserLogout(ctx context.Context, userID, ipAddress string) {
	event := AuditEvent{
		UserID:    userID,
		Action:    "logout",
		Resource:  "user",
		IPAddress: ipAddress,
		Timestamp: time.Now(),
	}

	al.LogEvent(ctx, event)
}

func (al *AuditLogger) LogDataAccess(ctx context.Context, userID, action, resource string, details map[string]interface{}) {
	event := AuditEvent{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Details:   details,
		Timestamp: time.Now(),
	}

	al.LogEvent(ctx, event)
}

type PerformanceLogger struct {
	logger *Logger
}

func NewPerformanceLogger(logger *Logger) *PerformanceLogger {
	return &PerformanceLogger{logger: logger}
}

func (pl *PerformanceLogger) LogDatabaseQuery(ctx context.Context, operation string, duration time.Duration, rows int, err error) {
	logger := pl.logger.WithContext(ctx)

	fields := []zap.Field{
		zap.String("db_operation", operation),
		zap.Duration("db_duration", duration),
		zap.Int("db_rows", rows),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		logger.Error("Database Query", fields...)
	} else {
		logger.Info("Database Query", fields...)
	}
}

func (pl *PerformanceLogger) LogCacheOperation(ctx context.Context, operation, key string, hit bool, duration time.Duration) {
	logger := pl.logger.WithContext(ctx)

	fields := []zap.Field{
		zap.String("cache_operation", operation),
		zap.String("cache_key", key),
		zap.Bool("cache_hit", hit),
		zap.Duration("cache_duration", duration),
	}

	logger.Info("Cache Operation", fields...)
}

func (pl *PerformanceLogger) LogExternalAPI(ctx context.Context, service, endpoint string, duration time.Duration, statusCode int, err error) {
	logger := pl.logger.WithContext(ctx)

	fields := []zap.Field{
		zap.String("api_service", service),
		zap.String("api_endpoint", endpoint),
		zap.Duration("api_duration", duration),
		zap.Int("api_status_code", statusCode),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		logger.Error("External API Call", fields...)
	} else {
		logger.Info("External API Call", fields...)
	}
}
