package storage

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// mockS3Client implements S3Client for testing.
type mockS3Client struct {
	objects map[string]*mockObject
}

type mockObject struct {
	data        []byte
	contentType string
	etag        string
	metadata    map[string]string
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{
		objects: make(map[string]*mockObject),
	}
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(params.Key)
	obj, exists := m.objects[key]
	if !exists {
		return nil, &s3types.NoSuchKey{}
	}

	size := int64(len(obj.data))
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(obj.data)),
		ContentLength: &size,
		ETag:          aws.String(obj.etag),
		ContentType:   aws.String(obj.contentType),
	}, nil
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	key := aws.ToString(params.Key)
	data, _ := io.ReadAll(params.Body)

	ct := "application/octet-stream"
	if params.ContentType != nil {
		ct = *params.ContentType
	}

	etag := "etag-" + key
	m.objects[key] = &mockObject{
		data:        data,
		contentType: ct,
		etag:        etag,
	}

	return &s3.PutObjectOutput{
		ETag: aws.String(etag),
	}, nil
}

func (m *mockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	key := aws.ToString(params.Key)
	obj, exists := m.objects[key]
	if !exists {
		return nil, &s3types.NoSuchKey{}
	}

	size := int64(len(obj.data))
	return &s3.HeadObjectOutput{
		ContentLength: &size,
		ETag:          aws.String(obj.etag),
		ContentType:   aws.String(obj.contentType),
		Metadata:      obj.metadata,
	}, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	key := aws.ToString(params.Key)
	delete(m.objects, key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	// Extract source key from CopySource (format: bucket/key)
	src := aws.ToString(params.CopySource)
	// Remove bucket prefix
	parts := bytes.SplitN([]byte(src), []byte("/"), 2)
	var srcKey string
	if len(parts) == 2 {
		srcKey = string(parts[1])
	} else {
		srcKey = src
	}

	srcObj, exists := m.objects[srcKey]
	if !exists {
		return nil, &s3types.NoSuchKey{}
	}

	destKey := aws.ToString(params.Key)
	m.objects[destKey] = &mockObject{
		data:        append([]byte(nil), srcObj.data...),
		contentType: srcObj.contentType,
		etag:        "etag-" + destKey,
		metadata:    srcObj.metadata,
	}

	return &s3.CopyObjectOutput{}, nil
}

func TestS3Storage_GetFileInfo(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["documents/test.docx"] = &mockObject{
		data:        []byte("hello world"),
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "abc123",
		metadata:    map[string]string{"owner": "testuser"},
	}

	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	info, err := store.GetFileInfo(ctx, "documents|test.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Name != "test.docx" {
		t.Errorf("expected name %q, got %q", "test.docx", info.Name)
	}
	if info.Size != 11 {
		t.Errorf("expected size 11, got %d", info.Size)
	}
	if info.Version != "abc123" {
		t.Errorf("expected version %q, got %q", "abc123", info.Version)
	}
	if info.Owner != "testuser" {
		t.Errorf("expected owner %q, got %q", "testuser", info.Owner)
	}
}

func TestS3Storage_GetFileInfo_NotFound(t *testing.T) {
	mock := newMockS3Client()
	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	_, err := store.GetFileInfo(ctx, "nonexistent.docx")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestS3Storage_GetFile(t *testing.T) {
	mock := newMockS3Client()
	content := []byte("file content here")
	mock.objects["test.docx"] = &mockObject{
		data:        content,
		contentType: "application/octet-stream",
		etag:        "version1",
	}

	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	body, info, err := store.GetFile(ctx, "test.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer body.Close()

	data, _ := io.ReadAll(body)
	if !bytes.Equal(data, content) {
		t.Errorf("expected content %q, got %q", content, data)
	}
	if info.Version != "version1" {
		t.Errorf("expected version %q, got %q", "version1", info.Version)
	}
}

func TestS3Storage_PutFile(t *testing.T) {
	mock := newMockS3Client()
	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	content := []byte("new content")
	version, err := store.PutFile(ctx, "test.docx", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}

	// Verify the file was stored
	obj, exists := mock.objects["test.docx"]
	if !exists {
		t.Fatal("expected file to be stored")
	}
	if !bytes.Equal(obj.data, content) {
		t.Errorf("stored content mismatch")
	}
}

func TestS3Storage_DeleteFile(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["test.docx"] = &mockObject{
		data: []byte("content"),
		etag: "v1",
	}

	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	err := store.DeleteFile(ctx, "test.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, exists := mock.objects["test.docx"]; exists {
		t.Error("expected file to be deleted")
	}
}

func TestS3Storage_RenameFile(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["docs/old.docx"] = &mockObject{
		data:        []byte("content"),
		contentType: "application/octet-stream",
		etag:        "v1",
	}

	store := NewS3StorageWithClient(mock, "test-bucket")
	ctx := context.Background()

	newID, err := store.RenameFile(ctx, "docs|old.docx", "new.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old file should be gone
	if _, exists := mock.objects["docs/old.docx"]; exists {
		t.Error("expected old file to be deleted")
	}

	// New file should exist
	if _, exists := mock.objects["docs/new.docx"]; !exists {
		t.Error("expected new file to exist")
	}

	if newID != "docs|new.docx" {
		t.Errorf("expected new file ID %q, got %q", "docs|new.docx", newID)
	}
}

func TestFileIDConversion(t *testing.T) {
	tests := []struct {
		fileID string
		key    string
	}{
		{"test.docx", "test.docx"},
		{"folder|test.docx", "folder/test.docx"},
		{"a|b|c.docx", "a/b/c.docx"},
	}

	for _, tt := range tests {
		key := fileIDToKey(tt.fileID)
		if key != tt.key {
			t.Errorf("fileIDToKey(%q) = %q, want %q", tt.fileID, key, tt.key)
		}

		fileID := keyToFileID(tt.key)
		if fileID != tt.fileID {
			t.Errorf("keyToFileID(%q) = %q, want %q", tt.key, fileID, tt.fileID)
		}
	}
}

func TestContentTypeForFile(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		{"test.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{"test.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
		{"test.pdf", "application/pdf"},
		{"test.txt", "text/plain"},
		{"test.unknown", "application/octet-stream"},
	}

	for _, tt := range tests {
		got := contentTypeForFile(tt.key)
		if got != tt.expected {
			t.Errorf("contentTypeForFile(%q) = %q, want %q", tt.key, got, tt.expected)
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	if IsNotFoundError(nil) {
		t.Error("expected nil error to not be NotFound")
	}

	nsk := &s3types.NoSuchKey{}
	if !IsNotFoundError(nsk) {
		t.Error("expected NoSuchKey to be NotFound")
	}
}
