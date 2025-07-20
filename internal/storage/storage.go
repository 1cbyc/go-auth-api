package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Storage struct {
	useS3   bool
	client  *minio.Client
	bucket  string
	baseURL string
}

func NewStorageFromEnv() (*Storage, error) {
	endpoint := os.Getenv("S3_ENDPOINT")
	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")
	bucket := os.Getenv("S3_BUCKET")
	useSSL := os.Getenv("S3_USE_SSL") == "true"
	region := os.Getenv("S3_REGION")
	if endpoint != "" && accessKey != "" && secretKey != "" && bucket != "" {
		client, err := minio.New(endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
			Secure: useSSL,
			Region: region,
		})
		if err != nil {
			return nil, err
		}
		return &Storage{useS3: true, client: client, bucket: bucket, baseURL: endpoint}, nil
	}
	return &Storage{useS3: false, baseURL: ""}, nil
}

func (s *Storage) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, dest string) (string, error) {
	if s.useS3 {
		_, err := s.client.PutObject(ctx, s.bucket, dest, file, fileHeader.Size, minio.PutObjectOptions{ContentType: fileHeader.Header.Get("Content-Type")})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s/%s/%s", s.baseURL, s.bucket, dest), nil
	}
	out, err := os.Create("." + dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}
	return dest, nil
}

func (s *Storage) GetFileURL(dest string) string {
	if s.useS3 {
		return fmt.Sprintf("%s/%s/%s", s.baseURL, s.bucket, dest)
	}
	return dest
} 
