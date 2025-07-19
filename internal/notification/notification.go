package notification

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// NotificationType represents the type of notification
type NotificationType string

const (
	EmailNotification NotificationType = "email"
	SMSNotification   NotificationType = "sms"
	PushNotification  NotificationType = "push"
)

// NotificationStatus represents the status of a notification
type NotificationStatus string

const (
	PendingStatus   NotificationStatus = "pending"
	SentStatus      NotificationStatus = "sent"
	DeliveredStatus NotificationStatus = "delivered"
	FailedStatus    NotificationStatus = "failed"
)

// Notification represents a notification
type Notification struct {
	ID          string            `json:"id"`
	Type        NotificationType  `json:"type"`
	Recipient   string            `json:"recipient"`
	Subject     string            `json:"subject,omitempty"`
	Content     string            `json:"content"`
	Template    string            `json:"template,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Status      NotificationStatus `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	SentAt      *time.Time        `json:"sent_at,omitempty"`
	DeliveredAt *time.Time        `json:"delivered_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	RetryCount  int               `json:"retry_count"`
	MaxRetries  int               `json:"max_retries"`
}

// NotificationService represents a notification service
type NotificationService struct {
	emailService *EmailService
	smsService   *SMSService
	pushService  *PushService
	templates    *TemplateManager
}

// NewNotificationService creates a new notification service
func NewNotificationService(config NotificationConfig) *NotificationService {
	return &NotificationService{
		emailService: NewEmailService(config.Email),
		smsService:   NewSMSService(config.SMS),
		pushService:  NewPushService(config.Push),
		templates:    NewTemplateManager(),
	}
}

// NotificationConfig represents notification configuration
type NotificationConfig struct {
	Email EmailConfig `json:"email"`
	SMS   SMSConfig   `json:"sms"`
	Push  PushConfig  `json:"push"`
}

// EmailConfig represents email configuration
type EmailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name"`
}

// SMSConfig represents SMS configuration
type SMSConfig struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	APISecret string `json:"api_secret"`
	From     string `json:"from"`
}

// PushConfig represents push notification configuration
type PushConfig struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// SendNotification sends a notification
func (ns *NotificationService) SendNotification(ctx context.Context, notification *Notification) error {
	// Process template if specified
	if notification.Template != "" {
		content, err := ns.templates.Render(notification.Template, notification.Data)
		if err != nil {
			return fmt.Errorf("failed to render template: %w", err)
		}
		notification.Content = content
	}
	
	// Send based on type
	switch notification.Type {
	case EmailNotification:
		return ns.emailService.Send(ctx, notification)
	case SMSNotification:
		return ns.smsService.Send(ctx, notification)
	case PushNotification:
		return ns.pushService.Send(ctx, notification)
	default:
		return fmt.Errorf("unsupported notification type: %s", notification.Type)
	}
}

// EmailService represents an email service
type EmailService struct {
	config EmailConfig
}

// NewEmailService creates a new email service
func NewEmailService(config EmailConfig) *EmailService {
	return &EmailService{config: config}
}

// Send sends an email notification
func (es *EmailService) Send(ctx context.Context, notification *Notification) error {
	// Update status
	notification.Status = PendingStatus
	
	// Prepare email
	to := []string{notification.Recipient}
	subject := notification.Subject
	body := notification.Content
	
	// Create message
	message := fmt.Sprintf("To: %s\r\n"+
		"From: %s <%s>\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", strings.Join(to, ","), es.config.FromName, es.config.FromEmail, subject, body)
	
	// Send email
	auth := smtp.PlainAuth("", es.config.SMTPUsername, es.config.SMTPPassword, es.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", es.config.SMTPHost, es.config.SMTPPort)
	
	err := smtp.SendMail(addr, auth, es.config.FromEmail, to, []byte(message))
	if err != nil {
		notification.Status = FailedStatus
		notification.Error = err.Error()
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	// Update status
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

// SMSService represents an SMS service
type SMSService struct {
	config SMSConfig
}

// NewSMSService creates a new SMS service
func NewSMSService(config SMSConfig) *SMSService {
	return &SMSService{config: config}
}

// Send sends an SMS notification
func (ss *SMSService) Send(ctx context.Context, notification *Notification) error {
	// Update status
	notification.Status = PendingStatus
	
	// In a real implementation, you would integrate with an SMS provider
	// For now, we'll simulate sending
	time.Sleep(100 * time.Millisecond)
	
	// Simulate success
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

// PushService represents a push notification service
type PushService struct {
	config PushConfig
}

// NewPushService creates a new push service
func NewPushService(config PushConfig) *PushService {
	return &PushService{config: config}
}

// Send sends a push notification
func (ps *PushService) Send(ctx context.Context, notification *Notification) error {
	// Update status
	notification.Status = PendingStatus
	
	// In a real implementation, you would integrate with a push notification provider
	// For now, we'll simulate sending
	time.Sleep(100 * time.Millisecond)
	
	// Simulate success
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

// TemplateManager manages notification templates
type TemplateManager struct {
	templates map[string]*template.Template
}

// NewTemplateManager creates a new template manager
func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}
	
	// Register default templates
	tm.registerDefaultTemplates()
	
	return tm
}

// registerDefaultTemplates registers default notification templates
func (tm *TemplateManager) registerDefaultTemplates() {
	// Welcome email template
	tm.RegisterTemplate("welcome_email", `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to Our Service</title>
</head>
<body>
    <h1>Welcome, {{.Name}}!</h1>
    <p>Thank you for registering with our service.</p>
    <p>Your account has been successfully created.</p>
    <p>If you have any questions, please don't hesitate to contact us.</p>
    <p>Best regards,<br>The Team</p>
</body>
</html>
`)
	
	// Password reset template
	tm.RegisterTemplate("password_reset", `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
</head>
<body>
    <h1>Password Reset Request</h1>
    <p>Hello {{.Name}},</p>
    <p>You have requested to reset your password.</p>
    <p>Click the link below to reset your password:</p>
    <p><a href="{{.ResetLink}}">Reset Password</a></p>
    <p>This link will expire in {{.ExpiryTime}}.</p>
    <p>If you didn't request this, please ignore this email.</p>
    <p>Best regards,<br>The Team</p>
</body>
</html>
`)
	
	// Email verification template
	tm.RegisterTemplate("email_verification", `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
</head>
<body>
    <h1>Verify Your Email</h1>
    <p>Hello {{.Name}},</p>
    <p>Please verify your email address by clicking the link below:</p>
    <p><a href="{{.VerificationLink}}">Verify Email</a></p>
    <p>This link will expire in {{.ExpiryTime}}.</p>
    <p>Best regards,<br>The Team</p>
</body>
</html>
`)
}

// RegisterTemplate registers a new template
func (tm *TemplateManager) RegisterTemplate(name, content string) error {
	tmpl, err := template.New(name).Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", name, err)
	}
	
	tm.templates[name] = tmpl
	return nil
}

// Render renders a template with data
func (tm *TemplateManager) Render(name string, data map[string]interface{}) (string, error) {
	tmpl, exists := tm.templates[name]
	if !exists {
		return "", fmt.Errorf("template %s not found", name)
	}
	
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}
	
	return buf.String(), nil
}

// NotificationHandler handles notification-related HTTP requests
type NotificationHandler struct {
	service *NotificationService
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(service *NotificationService) *NotificationHandler {
	return &NotificationHandler{service: service}
}

// SendNotification handles notification sending requests
func (nh *NotificationHandler) SendNotification(c *gin.Context) {
	var req struct {
		Type      NotificationType      `json:"type" binding:"required"`
		Recipient string                `json:"recipient" binding:"required"`
		Subject   string                `json:"subject,omitempty"`
		Content   string                `json:"content,omitempty"`
		Template  string                `json:"template,omitempty"`
		Data      map[string]interface{} `json:"data,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	// Create notification
	notification := &Notification{
		ID:         generateNotificationID(),
		Type:       req.Type,
		Recipient:  req.Recipient,
		Subject:    req.Subject,
		Content:    req.Content,
		Template:   req.Template,
		Data:       req.Data,
		Status:     PendingStatus,
		CreatedAt:  time.Now(),
		MaxRetries: 3,
	}
	
	// Send notification
	err := nh.service.SendNotification(c.Request.Context(), notification)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, gin.H{
		"message": "Notification sent successfully",
		"id":      notification.ID,
		"status":  notification.Status,
	})
}

// GetNotificationStatus gets the status of a notification
func (nh *NotificationHandler) GetNotificationStatus(c *gin.Context) {
	notificationID := c.Param("id")
	
	// In a real implementation, you would fetch from database
	// For now, we'll return a mock response
	c.JSON(200, gin.H{
		"id":     notificationID,
		"status": "sent",
		"sent_at": time.Now().Add(-5 * time.Minute),
	})
}

// generateNotificationID generates a unique notification ID
func generateNotificationID() string {
	return fmt.Sprintf("notif_%d", time.Now().UnixNano())
} 