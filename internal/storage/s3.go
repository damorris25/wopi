package storage

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// FileInfo contains metadata about a stored file.
type FileInfo struct {
	Name         string
	Size         int64
	Version      string // ETag or version identifier
	LastModified string
	ContentType  string
	Owner        string // Derived from metadata or default
}

// S3Client defines the subset of S3 operations used by the storage layer.
// This interface enables testing with mocks.
type S3Client interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
}

// S3Storage provides file operations backed by an S3-compatible object store.
type S3Storage struct {
	client S3Client
	bucket string
}

// S3Config holds configuration for the S3 storage backend.
type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey  string
	UseSSL          bool
	ForcePathStyle  bool
}

// NewS3Storage creates a new S3Storage using the provided configuration.
func NewS3Storage(ctx context.Context, cfg S3Config) (*S3Storage, error) {
	resolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               cfg.Endpoint,
				HostnameImmutable: cfg.ForcePathStyle,
			}, nil
		},
	)

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			"",
		)),
		config.WithEndpointResolverWithOptions(resolver),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.ForcePathStyle
	})

	return &S3Storage{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// NewS3StorageWithClient creates an S3Storage with a pre-configured client (for testing).
func NewS3StorageWithClient(client S3Client, bucket string) *S3Storage {
	return &S3Storage{
		client: client,
		bucket: bucket,
	}
}

// GetFileInfo retrieves metadata about a file.
func (s *S3Storage) GetFileInfo(ctx context.Context, fileID string) (*FileInfo, error) {
	key := fileIDToKey(fileID)

	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("head object %q: %w", key, err)
	}

	etag := ""
	if out.ETag != nil {
		etag = strings.Trim(*out.ETag, "\"")
	}

	contentType := "application/octet-stream"
	if out.ContentType != nil {
		contentType = *out.ContentType
	}

	owner := "system"
	if out.Metadata != nil {
		if v, ok := out.Metadata["owner"]; ok {
			owner = v
		}
	}

	lastModified := ""
	if out.LastModified != nil {
		lastModified = out.LastModified.UTC().Format("2006-01-02T15:04:05Z")
	}

	return &FileInfo{
		Name:         filepath.Base(key),
		Size:         safeContentLength(out.ContentLength),
		Version:      etag,
		LastModified: lastModified,
		ContentType:  contentType,
		Owner:        owner,
	}, nil
}

// GetFile retrieves the file contents.
func (s *S3Storage) GetFile(ctx context.Context, fileID string) (io.ReadCloser, *FileInfo, error) {
	key := fileIDToKey(fileID)

	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("get object %q: %w", key, err)
	}

	etag := ""
	if out.ETag != nil {
		etag = strings.Trim(*out.ETag, "\"")
	}

	info := &FileInfo{
		Name:    filepath.Base(key),
		Size:    safeContentLength(out.ContentLength),
		Version: etag,
	}

	return out.Body, info, nil
}

// PutFile writes file contents to storage.
func (s *S3Storage) PutFile(ctx context.Context, fileID string, body io.Reader, size int64) (version string, err error) {
	key := fileIDToKey(fileID)

	contentType := contentTypeForFile(key)

	out, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("put object %q: %w", key, err)
	}

	etag := ""
	if out.ETag != nil {
		etag = strings.Trim(*out.ETag, "\"")
	}

	return etag, nil
}

// DeleteFile removes a file from storage.
func (s *S3Storage) DeleteFile(ctx context.Context, fileID string) error {
	key := fileIDToKey(fileID)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("delete object %q: %w", key, err)
	}

	return nil
}

// RenameFile copies a file to a new key and deletes the old one.
func (s *S3Storage) RenameFile(ctx context.Context, fileID, newName string) (newFileID string, err error) {
	oldKey := fileIDToKey(fileID)
	dir := filepath.Dir(oldKey)
	newKey := filepath.Join(dir, newName)

	copySource := fmt.Sprintf("%s/%s", s.bucket, oldKey)

	_, err = s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(newKey),
		CopySource: aws.String(copySource),
	})
	if err != nil {
		return "", fmt.Errorf("copy object: %w", err)
	}

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(oldKey),
	})
	if err != nil {
		return "", fmt.Errorf("delete original after rename: %w", err)
	}

	return keyToFileID(newKey), nil
}

// fileIDToKey converts a WOPI file ID to an S3 object key.
// File IDs use dots as path separators to be URL-safe.
func fileIDToKey(fileID string) string {
	return strings.ReplaceAll(fileID, "|", "/")
}

// keyToFileID converts an S3 object key to a WOPI file ID.
func keyToFileID(key string) string {
	return strings.ReplaceAll(key, "/", "|")
}

func contentTypeForFile(key string) string {
	ext := strings.ToLower(filepath.Ext(key))
	types := map[string]string{
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".doc":  "application/msword",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".xls":  "application/vnd.ms-excel",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".ppt":  "application/vnd.ms-powerpoint",
		".pdf":  "application/pdf",
		".txt":  "text/plain",
		".csv":  "text/csv",
	}
	if ct, ok := types[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

func safeContentLength(cl *int64) int64 {
	if cl != nil {
		return *cl
	}
	return 0
}

// IsNotFoundError checks if an error is an S3 "not found" error.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var nsk *s3types.NoSuchKey
	if ok := isErrorType(err, &nsk); ok {
		return true
	}
	// Also check for "NotFound" in the error string for HeadObject 404s
	return strings.Contains(err.Error(), "NotFound") ||
		strings.Contains(err.Error(), "404") ||
		strings.Contains(err.Error(), "NoSuchKey")
}

// isErrorType is a helper for errors.As without importing errors in this file.
func isErrorType[T error](err error, target *T) bool {
	for err != nil {
		if e, ok := err.(T); ok {
			*target = e
			return true
		}
		if u, ok := err.(interface{ Unwrap() error }); ok {
			err = u.Unwrap()
		} else {
			return false
		}
	}
	return false
}
