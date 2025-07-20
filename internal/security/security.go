package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type SecurityConfig struct {
	EnableCORS            bool
	AllowedOrigins        []string
	EnableCSRF            bool
	CSRFSecret            string
	EnableRateLimiting    bool
	EnableSecurityHeaders bool
	TrustedProxies        []string
}

func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		EnableCORS:            true,
		AllowedOrigins:        []string{"http://localhost:3000", "https://yourdomain.com"},
		EnableCSRF:            true,
		CSRFSecret:            generateRandomSecret(32),
		EnableRateLimiting:    true,
		EnableSecurityHeaders: true,
		TrustedProxies:        []string{"127.0.0.1", "::1"},
	}
}

func SecurityMiddleware(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.EnableSecurityHeaders {
			setSecurityHeaders(c)
		}

		if config.EnableCORS {
			setupCORS(c, config.AllowedOrigins)
		}

		if config.EnableCSRF && c.Request.Method != "GET" && c.Request.Method != "HEAD" && c.Request.Method != "OPTIONS" {
			if !validateCSRFToken(c, config.CSRFSecret) {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token validation failed"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func setSecurityHeaders(c *gin.Context) {
	c.Header("X-Frame-Options", "DENY")

	c.Header("X-Content-Type-Options", "nosniff")

	c.Header("X-XSS-Protection", "1; mode=block")

	c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';")

	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

	c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func setupCORS(c *gin.Context, allowedOrigins []string) {
	origin := c.Request.Header.Get("Origin")

	allowed := false
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			allowed = true
			break
		}
	}

	if allowed {
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-CSRF-Token")
	}

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
}

func validateCSRFToken(c *gin.Context, secret string) bool {
	token := c.GetHeader("X-CSRF-Token")
	if token == "" {
		token = c.PostForm("csrf_token")
	}

	if token == "" {
		return false
	}

	return len(token) > 0
}

type InputValidator struct {
	emailRegex    *regexp.Regexp
	passwordRegex *regexp.Regexp
	usernameRegex *regexp.Regexp
}

func NewInputValidator() *InputValidator {
	return &InputValidator{
		emailRegex:    regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		passwordRegex: regexp.MustCompile(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$`),
		usernameRegex: regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`),
	}
}

func (v *InputValidator) ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	if !v.emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	if strings.Contains(email, "<script>") || strings.Contains(email, "javascript:") {
		return fmt.Errorf("email contains invalid characters")
	}

	return nil
}

func (v *InputValidator) ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if !v.passwordRegex.MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

func (v *InputValidator) ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}

	if !v.usernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-20 characters long and contain only letters, numbers, underscores, and hyphens")
	}

	return nil
}

func (v *InputValidator) SanitizeInput(input string) string {
	input = regexp.MustCompile(`<script[^>]*>.*?</script>`).ReplaceAllString(input, "")

	input = regexp.MustCompile(`javascript:`).ReplaceAllString(input, "")

	input = regexp.MustCompile(`on\w+\s*=`).ReplaceAllString(input, "")

	input = regexp.MustCompile(`<iframe[^>]*>.*?</iframe>`).ReplaceAllString(input, "")

	input = regexp.MustCompile(`<object[^>]*>.*?</object>`).ReplaceAllString(input, "")

	input = regexp.MustCompile(`<embed[^>]*>`).ReplaceAllString(input, "")

	return strings.TrimSpace(input)
}

func XSSProtectionMiddleware() gin.HandlerFunc {
	validator := NewInputValidator()

	return func(c *gin.Context) {
		for key, values := range c.Request.URL.Query() {
			for i, value := range values {
				values[i] = validator.SanitizeInput(value)
			}
			c.Request.URL.Query()[key] = values
		}

		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			if err := c.Request.ParseForm(); err == nil {
				for key, values := range c.Request.PostForm {
					for i, value := range values {
						values[i] = validator.SanitizeInput(value)
					}
					c.Request.PostForm[key] = values
				}
			}
		}

		c.Next()
	}
}

func SQLInjectionProtectionMiddleware() gin.HandlerFunc {
	sqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`),
		regexp.MustCompile(`(?i)(--|/\*|\*/|xp_|sp_)`),
		regexp.MustCompile(`(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)`),
		regexp.MustCompile(`(?i)('|"|;|\-\-|\/\*|\*\/)`),
	}

	return func(c *gin.Context) {
		for _, values := range c.Request.URL.Query() {
			for _, value := range values {
				for _, pattern := range sqlPatterns {
					if pattern.MatchString(value) {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
						c.Abort()
						return
					}
				}
			}
		}

		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			if err := c.Request.ParseForm(); err == nil {
				for _, values := range c.Request.PostForm {
					for _, value := range values {
						for _, pattern := range sqlPatterns {
							if pattern.MatchString(value) {
								c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
								c.Abort()
								return
							}
						}
					}
				}
			}
		}

		c.Next()
	}
}

func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func TrustedProxyMiddleware(trustedProxies []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		for _, proxy := range trustedProxies {
			if clientIP == proxy {
				if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
					ips := strings.Split(forwardedFor, ",")
					if len(ips) > 0 {
						c.Request.RemoteAddr = strings.TrimSpace(ips[0])
					}
				}
				break
			}
		}

		c.Next()
	}
}

type SecurityAuditor struct {
	auditLog chan SecurityEvent
}

type SecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	UserID      string    `json:"user_id,omitempty"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
}

func NewSecurityAuditor() *SecurityAuditor {
	auditor := &SecurityAuditor{
		auditLog: make(chan SecurityEvent, 100),
	}

	go auditor.processAuditLog()

	return auditor
}

func (sa *SecurityAuditor) LogSecurityEvent(event SecurityEvent) {
	sa.auditLog <- event
}

func (sa *SecurityAuditor) processAuditLog() {
	for event := range sa.auditLog {
		fmt.Printf("SECURITY EVENT: %s - %s - %s - %s\n",
			event.Timestamp.Format(time.RFC3339),
			event.EventType,
			event.IPAddress,
			event.Description)
	}
}

func SecurityAuditMiddleware(auditor *SecurityAuditor) gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.Request.UserAgent()
		ipAddress := c.ClientIP()

		suspiciousPatterns := []string{
			"sqlmap", "nikto", "nmap", "wget", "curl",
			"python", "perl", "ruby", "php",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(userAgent), pattern) {
				auditor.LogSecurityEvent(SecurityEvent{
					Timestamp:   time.Now(),
					EventType:   "suspicious_user_agent",
					IPAddress:   ipAddress,
					UserAgent:   userAgent,
					Description: fmt.Sprintf("Suspicious user agent detected: %s", userAgent),
					Severity:    "medium",
				})
				break
			}
		}


		c.Next()
	}
}
