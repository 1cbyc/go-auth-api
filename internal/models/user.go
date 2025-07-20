package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID                  string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Username            string         `json:"username" gorm:"uniqueIndex;not null;index"`
	Email               string         `json:"email" gorm:"uniqueIndex;not null;index"`
	Password            string         `json:"-" gorm:"not null"` // "-" means this field won't be included in JSON
	FirstName           string         `json:"first_name" gorm:"not null"`
	LastName            string         `json:"last_name" gorm:"not null"`
	Role                string         `json:"role" gorm:"not null;default:'user'"`
	IsActive            bool           `json:"is_active" gorm:"not null;default:true"`
	IsEmailVerified     bool           `json:"is_email_verified" gorm:"not null;default:false"` // added
	TwoFAEnabled        bool           `json:"two_fa_enabled" gorm:"not null;default:false"`    // 2FA enabled
	TwoFASecret         string         `json:"-" gorm:"not null;default:''"`                    // 2FA secret, omit in JSON
	FailedLoginAttempts int            `json:"failed_login_attempts" gorm:"not null;default:0"` // lockout
	LockoutUntil        *time.Time     `json:"lockout_until" gorm:"default:null"`               // lockout
	CreatedAt           time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt           time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt           gorm.DeletedAt `json:"-" gorm:"index"`
	Bio                 string         `json:"bio" gorm:"type:text"`
	Phone               string         `json:"phone" gorm:"type:varchar(32)"`
	Address             string         `json:"address" gorm:"type:text"`
	AvatarURL           string         `json:"avatar_url" gorm:"type:text"`
	Preferences         string         `json:"preferences" gorm:"type:jsonb;default:'{}'"`
}

type RefreshToken struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string    `json:"user_id" gorm:"not null;type:uuid"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	User      User      `json:"-" gorm:"foreignKey:UserID"`
}

type PasswordResetToken struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string    `json:"user_id" gorm:"not null;type:uuid"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	Used      bool      `json:"used" gorm:"not null;default:false"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	User      User      `json:"-" gorm:"foreignKey:UserID"`
}

type EmailVerificationToken struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string    `json:"user_id" gorm:"not null;type:uuid"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	Used      bool      `json:"used" gorm:"not null;default:false"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	User      User      `json:"-" gorm:"foreignKey:UserID"`
}

type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
}

type CreateUserRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Role      string `json:"role,omitempty"`
}

type UpdateUserRequest struct {
	Username  string `json:"username,omitempty" validate:"omitempty,min=3,max=50,alphanum"`
	Email     string `json:"email,omitempty" validate:"omitempty,email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Role      string `json:"role,omitempty"`
	IsActive  *bool  `json:"is_active,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	User         User   `json:"user"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type TwoFASetupRequest struct {
	UserID string `json:"user_id" validate:"required"`
}

type TwoFASetupResponse struct {
	Secret  string `json:"secret"`
	OTPAuth string `json:"otpauth_url"`
}

type TwoFAVerifyRequest struct {
	UserID string `json:"user_id" validate:"required"`
	Code   string `json:"code" validate:"required"`
}

type UserActivityLog struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string    `json:"user_id" gorm:"not null;type:uuid;index:user_activity_userid_createdat,priority:1"`
	Action    string    `json:"action" gorm:"not null"`
	Details   string    `json:"details" gorm:"type:text"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime;index:user_activity_userid_createdat,priority:2"`
}

func NewUser(req CreateUserRequest) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	role := req.Role
	if role == "" {
		role = "user"
	}

	user := &User{
		ID:              uuid.New().String(),
		Username:        req.Username,
		Email:           req.Email,
		Password:        string(hashedPassword),
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Role:            role,
		IsActive:        true,
		IsEmailVerified: false, // Default to false
	}

	return user, nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u *User) UpdatePassword(newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hashedPassword)
	u.UpdatedAt = time.Now()
	return nil
}

func (u *User) HasRole(role string) bool {
	return u.Role == role
}

func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

func (u *User) Update(req UpdateUserRequest) {
	if req.Username != "" {
		u.Username = req.Username
	}
	if req.Email != "" {
		u.Email = req.Email
	}
	if req.FirstName != "" {
		u.FirstName = req.FirstName
	}
	if req.LastName != "" {
		u.LastName = req.LastName
	}
	if req.Role != "" {
		u.Role = req.Role
	}
	if req.IsActive != nil {
		u.IsActive = *req.IsActive
	}
	u.UpdatedAt = time.Now()
}

func (u *User) Sanitize() {
	u.Password = ""
}

func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}
