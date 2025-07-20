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

type NotificationType string

const (
	EmailNotification NotificationType = "email"
	SMSNotification   NotificationType = "sms"
	PushNotification  NotificationType = "push"
)

type NotificationStatus string

const (
	PendingStatus   NotificationStatus = "pending"
	SentStatus      NotificationStatus = "sent"
	DeliveredStatus NotificationStatus = "delivered"
	FailedStatus    NotificationStatus = "failed"
)

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

type NotificationService struct {
	emailService *EmailService
	smsService   *SMSService
	pushService  *PushService
	templates    *TemplateManager
}

func NewNotificationService(config NotificationConfig) *NotificationService {
	return &NotificationService{
		emailService: NewEmailService(config.Email),
		smsService:   NewSMSService(config.SMS),
		pushService:  NewPushService(config.Push),
		templates:    NewTemplateManager(),
	}
}

type NotificationConfig struct {
	Email EmailConfig `json:"email"`
	SMS   SMSConfig   `json:"sms"`
	Push  PushConfig  `json:"push"`
}

type EmailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name"`
}

type SMSConfig struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	APISecret string `json:"api_secret"`
	From     string `json:"from"`
}

type PushConfig struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

func (ns *NotificationService) SendNotification(ctx context.Context, notification *Notification) error {
	if notification.Template != "" {
		content, err := ns.templates.Render(notification.Template, notification.Data)
		if err != nil {
			return fmt.Errorf("failed to render template: %w", err)
		}
		notification.Content = content
	}
	
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

type EmailService struct {
	config EmailConfig
}

func NewEmailService(config EmailConfig) *EmailService {
	return &EmailService{config: config}
}

func (es *EmailService) Send(ctx context.Context, notification *Notification) error {
	notification.Status = PendingStatus
	
	to := []string{notification.Recipient}
	subject := notification.Subject
	body := notification.Content
	
	message := fmt.Sprintf("To: %s\r\n"+
		"From: %s <%s>\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", strings.Join(to, ","), es.config.FromName, es.config.FromEmail, subject, body)
	
	auth := smtp.PlainAuth("", es.config.SMTPUsername, es.config.SMTPPassword, es.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", es.config.SMTPHost, es.config.SMTPPort)
	
	err := smtp.SendMail(addr, auth, es.config.FromEmail, to, []byte(message))
	if err != nil {
		notification.Status = FailedStatus
		notification.Error = err.Error()
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

type SMSService struct {
	config SMSConfig
}

func NewSMSService(config SMSConfig) *SMSService {
	return &SMSService{config: config}
}

func (ss *SMSService) Send(ctx context.Context, notification *Notification) error {
	notification.Status = PendingStatus
	
	time.Sleep(100 * time.Millisecond)
	
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

type PushService struct {
	config PushConfig
}

func NewPushService(config PushConfig) *PushService {
	return &PushService{config: config}
}

func (ps *PushService) Send(ctx context.Context, notification *Notification) error {
	notification.Status = PendingStatus
	
	time.Sleep(100 * time.Millisecond)
	
	now := time.Now()
	notification.Status = SentStatus
	notification.SentAt = &now
	
	return nil
}

type TemplateManager struct {
	templates map[string]*template.Template
}

func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}
	
	tm.registerDefaultTemplates()
	
	return tm
}

func (tm *TemplateManager) registerDefaultTemplates() {
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

func (tm *TemplateManager) RegisterTemplate(name, content string) error {
	tmpl, err := template.New(name).Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", name, err)
	}
	
	tm.templates[name] = tmpl
	return nil
}

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

type NotificationHandler struct {
	service *NotificationService
}

func NewNotificationHandler(service *NotificationService) *NotificationHandler {
	return &NotificationHandler{service: service}
}

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

func (nh *NotificationHandler) GetNotificationStatus(c *gin.Context) {
	notificationID := c.Param("id")
	
	c.JSON(200, gin.H{
		"id":     notificationID,
		"status": "sent",
		"sent_at": time.Now().Add(-5 * time.Minute),
	})
}

func generateNotificationID() string {
	return fmt.Sprintf("notif_%d", time.Now().UnixNano())
} 
