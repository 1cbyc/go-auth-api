package repository

import (
	"fmt"
	"time"

	"go-auth-api/internal/models"

	"gorm.io/gorm"
)

type GORMUserRepository struct {
	db *gorm.DB
}

func NewGORMUserRepository(db *gorm.DB) UserRepository {
	return &GORMUserRepository{db: db}
}

func (r *GORMUserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *GORMUserRepository) GetByID(id string) (*models.User, error) {
	var user models.User
	err := r.db.Where("id = ?", id).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (r *GORMUserRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (r *GORMUserRepository) GetByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (r *GORMUserRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

func (r *GORMUserRepository) Delete(id string) error {
	return r.db.Where("id = ?", id).Delete(&models.User{}).Error
}

func (r *GORMUserRepository) List(offset, limit int) ([]*models.User, error) {
	var users []*models.User
	err := r.db.Offset(offset).Limit(limit).Find(&users).Error
	return users, err
}

func (r *GORMUserRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.User{}).Count(&count).Error
	return count, err
}

func (r *GORMUserRepository) LogUserActivity(userID, action, details string) error {
	log := &models.UserActivityLog{
		UserID:    userID,
		Action:    action,
		Details:   details,
		CreatedAt: time.Now(),
	}
	return r.db.Create(log).Error
}

func (r *GORMUserRepository) ListUserActivityLogs(userID string, limit, offset int) ([]*models.UserActivityLog, error) {
	var logs []*models.UserActivityLog
	db := r.db
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if err := db.Order("created_at desc").Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

type GORMRefreshTokenRepository struct {
	db *gorm.DB
}

func NewGORMRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository {
	return &GORMRefreshTokenRepository{db: db}
}

func (r *GORMRefreshTokenRepository) Create(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *GORMRefreshTokenRepository) GetByToken(token string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	err := r.db.Where("token = ?", token).First(&rt).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rt, nil
}

func (r *GORMRefreshTokenRepository) DeleteByToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error
}

func (r *GORMRefreshTokenRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.RefreshToken{}).Error
}

type GORMPasswordResetTokenRepository struct {
	db *gorm.DB
}

func NewGORMPasswordResetTokenRepository(db *gorm.DB) PasswordResetTokenRepository {
	return &GORMPasswordResetTokenRepository{db: db}
}

func (r *GORMPasswordResetTokenRepository) Create(token *models.PasswordResetToken) error {
	return r.db.Create(token).Error
}

func (r *GORMPasswordResetTokenRepository) GetByToken(token string) (*models.PasswordResetToken, error) {
	var prt models.PasswordResetToken
	err := r.db.Where("token = ?", token).First(&prt).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &prt, nil
}

func (r *GORMPasswordResetTokenRepository) MarkUsed(token string) error {
	return r.db.Model(&models.PasswordResetToken{}).Where("token = ?", token).Update("used", true).Error
}

func (r *GORMPasswordResetTokenRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.PasswordResetToken{}).Error
}

type GORMEmailVerificationTokenRepository struct {
	db *gorm.DB
}

func NewGORMEmailVerificationTokenRepository(db *gorm.DB) EmailVerificationTokenRepository {
	return &GORMEmailVerificationTokenRepository{db: db}
}

func (r *GORMEmailVerificationTokenRepository) Create(token *models.EmailVerificationToken) error {
	return r.db.Create(token).Error
}

func (r *GORMEmailVerificationTokenRepository) GetByToken(token string) (*models.EmailVerificationToken, error) {
	var evt models.EmailVerificationToken
	err := r.db.Where("token = ?", token).First(&evt).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &evt, nil
}

func (r *GORMEmailVerificationTokenRepository) MarkUsed(token string) error {
	return r.db.Model(&models.EmailVerificationToken{}).Where("token = ?", token).Update("used", true).Error
}

func (r *GORMEmailVerificationTokenRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.EmailVerificationToken{}).Error
}
