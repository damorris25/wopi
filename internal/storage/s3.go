package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	Owner        string            // Derived from metadata or default
	Metadata     map[string]string // Raw S3 user metadata (without x-amz-meta- prefix)
}

// S3Client defines the subset of S3 operations used by the storage layer.
// This interface enables testing with mocks.
type S3Client interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// FileListItem represents a file entry returned by ListFiles.
type FileListItem struct {
	FileID  string `json:"file_id"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	LastMod string `json:"last_modified,omitempty"`
}

// FolderListItem represents a subfolder entry returned by ListFilesInFolder.
type FolderListItem struct {
	Name   string `json:"name"`   // e.g. "subfolder"
	Prefix string `json:"prefix"` // e.g. "docs/subfolder/"
}

// FolderListing holds the files and subfolders at a given prefix.
type FolderListing struct {
	Files   []FileListItem   `json:"files"`
	Folders []FolderListItem `json:"folders"`
}

// S3Storage provides file operations backed by an S3-compatible object store.
type S3Storage struct {
	client S3Client
	bucket string
}

// S3Config holds configuration for the S3 storage backend.
type S3Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKeyID    string
	SecretAccessKey string
	UseSSL         bool
	ForcePathStyle bool

	// BearerAuth enables OIDC bearer token injection for S3 proxy auth.
	// When set, a BearerTokenTransport wraps the HTTP client so every
	// request carries an Authorization header obtained via client credentials.
	BearerAuth *BearerAuthConfig
}

// BearerAuthConfig holds the credentials needed to obtain OIDC bearer tokens
// for authenticating to an S3-compatible proxy (e.g. Virtru Secure Object Proxy).
type BearerAuthConfig struct {
	TokenURL     string // OIDC token endpoint
	ClientID     string
	ClientSecret string
	Logger       *slog.Logger // optional; logs token source per request
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

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			"",
		)),
		config.WithEndpointResolverWithOptions(resolver),
	}

	// When bearer auth is configured, wrap the HTTP client so every S3
	// request carries an OIDC bearer token for the proxy.
	if cfg.BearerAuth != nil {
		transport := &BearerTokenTransport{
			TokenURL:     cfg.BearerAuth.TokenURL,
			ClientID:     cfg.BearerAuth.ClientID,
			ClientSecret: cfg.BearerAuth.ClientSecret,
			Logger:       cfg.BearerAuth.Logger,
		}
		opts = append(opts, config.WithHTTPClient(&http.Client{Transport: transport}))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.ForcePathStyle
		// Disable request checksums so PutObject works with unseekable
		// streams over plain HTTP (e.g. when proxying through s4proxy).
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
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
	if err := validateFileID(fileID); err != nil {
		return nil, err
	}
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
		Metadata:     out.Metadata,
	}, nil
}

// GetFile retrieves the file contents.
func (s *S3Storage) GetFile(ctx context.Context, fileID string) (io.ReadCloser, *FileInfo, error) {
	if err := validateFileID(fileID); err != nil {
		return nil, nil, err
	}
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

	contentType := "application/octet-stream"
	if out.ContentType != nil {
		contentType = *out.ContentType
	}

	info := &FileInfo{
		Name:        filepath.Base(key),
		Size:        safeContentLength(out.ContentLength),
		Version:     etag,
		ContentType: contentType,
	}

	return out.Body, info, nil
}

// PutFile writes file contents to storage.
func (s *S3Storage) PutFile(ctx context.Context, fileID string, body io.Reader, size int64) (version string, err error) {
	if err := validateFileID(fileID); err != nil {
		return "", err
	}
	key := fileIDToKey(fileID)

	contentType := contentTypeForFile(key)

	// Buffer the body so the AWS SDK can seek for payload signing.
	seekBody, err := toSeekableReader(body)
	if err != nil {
		return "", fmt.Errorf("buffering body for %q: %w", key, err)
	}

	out, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          seekBody,
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
	if err := validateFileID(fileID); err != nil {
		return err
	}
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
	if err := validateFileID(fileID); err != nil {
		return "", err
	}
	// Validate newName: reject path separators and traversal sequences.
	if strings.ContainsAny(newName, "/\\|") || newName == ".." || newName == "." || newName == "" {
		return "", fmt.Errorf("invalid file name: %q", newName)
	}
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

// ListFiles returns all objects in the bucket with the given prefix.
func (s *S3Storage) ListFiles(ctx context.Context, prefix string) ([]FileListItem, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}

	var items []FileListItem
	for {
		out, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range out.Contents {
			key := aws.ToString(obj.Key)
			// Skip "directory" markers (keys ending with /)
			if strings.HasSuffix(key, "/") {
				continue
			}
			lastMod := ""
			if obj.LastModified != nil {
				lastMod = obj.LastModified.UTC().Format("2006-01-02T15:04:05Z")
			}
			items = append(items, FileListItem{
				FileID:  keyToFileID(key),
				Name:    filepath.Base(key),
				Size:    safeContentLength(obj.Size),
				LastMod: lastMod,
			})
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		input.ContinuationToken = out.NextContinuationToken
	}
	return items, nil
}

// ListFilesInFolder returns files and subfolders at the given prefix using
// the S3 delimiter convention. Unlike ListFiles it does not recurse into
// subfolders.
func (s *S3Storage) ListFilesInFolder(ctx context.Context, prefix string) (*FolderListing, error) {
	delimiter := "/"
	input := &s3.ListObjectsV2Input{
		Bucket:    aws.String(s.bucket),
		Delimiter: aws.String(delimiter),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}

	listing := &FolderListing{}
	for {
		out, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list objects in folder: %w", err)
		}

		for _, obj := range out.Contents {
			key := aws.ToString(obj.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}
			lastMod := ""
			if obj.LastModified != nil {
				lastMod = obj.LastModified.UTC().Format("2006-01-02T15:04:05Z")
			}
			listing.Files = append(listing.Files, FileListItem{
				FileID:  keyToFileID(key),
				Name:    filepath.Base(key),
				Size:    safeContentLength(obj.Size),
				LastMod: lastMod,
			})
		}

		for _, cp := range out.CommonPrefixes {
			p := aws.ToString(cp.Prefix)
			name := strings.TrimSuffix(strings.TrimPrefix(p, prefix), "/")
			listing.Folders = append(listing.Folders, FolderListItem{
				Name:   name,
				Prefix: p,
			})
		}

		if !aws.ToBool(out.IsTruncated) {
			break
		}
		input.ContinuationToken = out.NextContinuationToken
	}

	if listing.Files == nil {
		listing.Files = []FileListItem{}
	}
	if listing.Folders == nil {
		listing.Folders = []FolderListItem{}
	}

	return listing, nil
}

// PutFileWithMetadata writes file contents to storage with custom S3 metadata.
// When metadata is nil or empty it behaves identically to PutFile.
func (s *S3Storage) PutFileWithMetadata(ctx context.Context, fileID string, body io.Reader, size int64, metadata map[string]string) (version string, err error) {
	if err := validateFileID(fileID); err != nil {
		return "", err
	}
	key := fileIDToKey(fileID)
	contentType := contentTypeForFile(key)

	// Buffer the body so the AWS SDK can seek for payload signing.
	seekBody, err := toSeekableReader(body)
	if err != nil {
		return "", fmt.Errorf("buffering body for %q: %w", key, err)
	}

	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          seekBody,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}

	out, err := s.client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("put object %q: %w", key, err)
	}

	etag := ""
	if out.ETag != nil {
		etag = strings.Trim(*out.ETag, "\"")
	}
	return etag, nil
}

// maxUploadSize is the maximum body size accepted by PutFile (256 MB).
const maxUploadSize = 256 << 20

// toSeekableReader ensures the reader is seekable (required by the AWS SDK
// for payload signing). If the reader already implements io.ReadSeeker it is
// returned as-is; otherwise the content is buffered into a bytes.Reader.
// Reads are limited to maxUploadSize to prevent memory exhaustion.
func toSeekableReader(r io.Reader) (io.ReadSeeker, error) {
	if rs, ok := r.(io.ReadSeeker); ok {
		return rs, nil
	}
	limited := io.LimitReader(r, maxUploadSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxUploadSize {
		return nil, fmt.Errorf("request body exceeds %d byte limit", maxUploadSize)
	}
	return bytes.NewReader(data), nil
}

// validateFileID checks that a file ID does not contain path traversal
// sequences or other unsafe patterns that could escape the bucket keyspace.
func validateFileID(fileID string) error {
	if fileID == "" {
		return fmt.Errorf("empty file ID")
	}
	key := strings.ReplaceAll(fileID, "|", "/")
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("absolute path in file ID")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("path traversal in file ID")
		}
	}
	return nil
}

// fileIDToKey converts a WOPI file ID to an S3 object key.
// File IDs use pipes as path separators to be URL-safe.
func fileIDToKey(fileID string) string {
	return strings.ReplaceAll(fileID, "|", "/")
}

// keyToFileID converts an S3 object key to a WOPI file ID.
func keyToFileID(key string) string {
	return strings.ReplaceAll(key, "/", "|")
}

// KeyToFileID is the exported version of keyToFileID for use by other packages.
func KeyToFileID(key string) string {
	return keyToFileID(key)
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
