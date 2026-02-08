package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/wopi"
)

// mockS3Client implements storage.S3Client for handler tests.
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
	return &mockS3Client{objects: make(map[string]*mockObject)}
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
	m.objects[key] = &mockObject{data: data, contentType: ct, etag: etag}
	return &s3.PutObjectOutput{ETag: aws.String(etag)}, nil
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
	src := aws.ToString(params.CopySource)
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

func newTestHandler() (*Handler, *mockS3Client) {
	mock := newMockS3Client()
	s3Store := storage.NewS3StorageWithClient(mock, "test-bucket")
	lockMgr := wopi.NewLockManager(30 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &Handler{
		Storage:     s3Store,
		LockManager: lockMgr,
		Logger:      logger,
		BaseURL:     "http://localhost:8080",
	}

	return h, mock
}

func requestWithContext(method, path string, body io.Reader, fileID, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	ctx := context.WithValue(req.Context(), middleware.FileIDKey, fileID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	return req.WithContext(ctx)
}

func TestCheckFileInfo(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data:        []byte("hello"),
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
		metadata:    map[string]string{"owner": "alice"},
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/test.docx", nil, "test.docx", "user1")
	rec := httptest.NewRecorder()

	h.CheckFileInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp wopi.CheckFileInfoResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.BaseFileName != "test.docx" {
		t.Errorf("expected BaseFileName %q, got %q", "test.docx", resp.BaseFileName)
	}
	if resp.Size != 5 {
		t.Errorf("expected Size 5, got %d", resp.Size)
	}
	if resp.OwnerId != "alice" {
		t.Errorf("expected OwnerId %q, got %q", "alice", resp.OwnerId)
	}
	if resp.UserId != "user1" {
		t.Errorf("expected UserId %q, got %q", "user1", resp.UserId)
	}
	if resp.Version != "v1" {
		t.Errorf("expected Version %q, got %q", "v1", resp.Version)
	}
	if !resp.SupportsLocks {
		t.Error("expected SupportsLocks to be true")
	}
	if !resp.SupportsUpdate {
		t.Error("expected SupportsUpdate to be true")
	}
	if !resp.UserCanWrite {
		t.Error("expected UserCanWrite to be true")
	}
}

func TestCheckFileInfo_NotFound(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodGet, "/wopi/files/missing.docx", nil, "missing.docx", "user1")
	rec := httptest.NewRecorder()

	h.CheckFileInfo(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetFile(t *testing.T) {
	h, mock := newTestHandler()

	content := []byte("file content here")
	mock.objects["test.docx"] = &mockObject{
		data:        content,
		contentType: "application/octet-stream",
		etag:        "v1",
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/test.docx/contents", nil, "test.docx", "user1")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.Bytes()
	if !bytes.Equal(body, content) {
		t.Errorf("expected content %q, got %q", content, body)
	}

	if v := rec.Header().Get(wopi.HeaderItemVersion); v != "v1" {
		t.Errorf("expected version header %q, got %q", "v1", v)
	}
}

func TestGetFile_NotFound(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodGet, "/wopi/files/missing.docx/contents", nil, "missing.docx", "user1")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetFile_TooLarge(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["big.docx"] = &mockObject{
		data:        make([]byte, 1000),
		contentType: "application/octet-stream",
		etag:        "v1",
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/big.docx/contents", nil, "big.docx", "user1")
	req.Header.Set(wopi.HeaderMaxExpectedSize, "100")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", rec.Code)
	}
}

func TestPutFile_WithLock(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data: []byte("old content"),
		etag: "v1",
	}

	// Lock the file
	h.LockManager.Lock("test.docx", "lock-123")

	// PutFile with correct lock
	newContent := []byte("new content")
	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx/contents", bytes.NewReader(newContent), "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	req.Header.Set(wopi.HeaderLock, "lock-123")
	req.ContentLength = int64(len(newContent))
	rec := httptest.NewRecorder()

	h.PutFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestPutFile_LockMismatch(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data: []byte("content"),
		etag: "v1",
	}

	h.LockManager.Lock("test.docx", "lock-123")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx/contents", bytes.NewReader([]byte("new")), "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	req.Header.Set(wopi.HeaderLock, "wrong-lock")
	rec := httptest.NewRecorder()

	h.PutFile(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}

	if got := rec.Header().Get(wopi.HeaderLock); got != "lock-123" {
		t.Errorf("expected lock header %q, got %q", "lock-123", got)
	}
}

func TestPutFile_UnlockedEmptyFile(t *testing.T) {
	h, mock := newTestHandler()

	// Empty file (zero bytes) — should allow PutFile without lock
	mock.objects["new.docx"] = &mockObject{
		data: []byte{},
		etag: "v0",
	}

	content := []byte("initial content")
	req := requestWithContext(http.MethodPost, "/wopi/files/new.docx/contents", bytes.NewReader(content), "new.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	req.ContentLength = int64(len(content))
	rec := httptest.NewRecorder()

	h.PutFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty file PutFile, got %d", rec.Code)
	}
}

func TestPutFile_UnlockedNonEmptyFile(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["existing.docx"] = &mockObject{
		data: []byte("existing content"),
		etag: "v1",
	}

	req := requestWithContext(http.MethodPost, "/wopi/files/existing.docx/contents", bytes.NewReader([]byte("new")), "existing.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	rec := httptest.NewRecorder()

	h.PutFile(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for unlocked non-empty file, got %d", rec.Code)
	}
}

func TestLock(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideLock)
	req.Header.Set(wopi.HeaderLock, "lock-abc")
	rec := httptest.NewRecorder()

	h.Lock(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Verify lock was set
	if got := h.LockManager.GetLock("test.docx"); got != "lock-abc" {
		t.Errorf("expected lock %q, got %q", "lock-abc", got)
	}
}

func TestLock_MissingHeader(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideLock)
	rec := httptest.NewRecorder()

	h.Lock(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLock_Conflict(t *testing.T) {
	h, _ := newTestHandler()

	h.LockManager.Lock("test.docx", "lock-existing")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideLock)
	req.Header.Set(wopi.HeaderLock, "lock-different")
	rec := httptest.NewRecorder()

	h.Lock(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}

	if got := rec.Header().Get(wopi.HeaderLock); got != "lock-existing" {
		t.Errorf("expected current lock %q, got %q", "lock-existing", got)
	}
}

func TestGetLock(t *testing.T) {
	h, _ := newTestHandler()

	// No lock
	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideGetLock)
	rec := httptest.NewRecorder()

	h.GetLock(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get(wopi.HeaderLock); got != "" {
		t.Errorf("expected empty lock, got %q", got)
	}

	// With lock
	h.LockManager.Lock("test.docx", "lock-xyz")
	req = requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	rec = httptest.NewRecorder()
	h.GetLock(rec, req)

	if got := rec.Header().Get(wopi.HeaderLock); got != "lock-xyz" {
		t.Errorf("expected lock %q, got %q", "lock-xyz", got)
	}
}

func TestRefreshLock(t *testing.T) {
	h, _ := newTestHandler()

	h.LockManager.Lock("test.docx", "lock-123")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRefreshLock)
	req.Header.Set(wopi.HeaderLock, "lock-123")
	rec := httptest.NewRecorder()

	h.RefreshLock(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRefreshLock_Mismatch(t *testing.T) {
	h, _ := newTestHandler()

	h.LockManager.Lock("test.docx", "lock-123")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRefreshLock)
	req.Header.Set(wopi.HeaderLock, "wrong-lock")
	rec := httptest.NewRecorder()

	h.RefreshLock(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestUnlock(t *testing.T) {
	h, _ := newTestHandler()

	h.LockManager.Lock("test.docx", "lock-123")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideUnlock)
	req.Header.Set(wopi.HeaderLock, "lock-123")
	rec := httptest.NewRecorder()

	h.Unlock(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if got := h.LockManager.GetLock("test.docx"); got != "" {
		t.Errorf("expected empty lock after unlock, got %q", got)
	}
}

func TestUnlockAndRelock(t *testing.T) {
	h, _ := newTestHandler()

	h.LockManager.Lock("test.docx", "lock-old")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideUnlockAndRelock)
	req.Header.Set(wopi.HeaderLock, "lock-new")
	req.Header.Set(wopi.HeaderOldLock, "lock-old")
	rec := httptest.NewRecorder()

	h.UnlockAndRelock(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if got := h.LockManager.GetLock("test.docx"); got != "lock-new" {
		t.Errorf("expected lock %q, got %q", "lock-new", got)
	}
}

func TestDeleteFile(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data: []byte("content"),
		etag: "v1",
	}

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideDelete)
	rec := httptest.NewRecorder()

	h.DeleteFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if _, exists := mock.objects["test.docx"]; exists {
		t.Error("expected file to be deleted")
	}
}

func TestDeleteFile_Locked(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data: []byte("content"),
		etag: "v1",
	}

	h.LockManager.Lock("test.docx", "lock-123")

	// Try to delete with wrong lock
	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideDelete)
	req.Header.Set(wopi.HeaderLock, "wrong-lock")
	rec := httptest.NewRecorder()

	h.DeleteFile(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for locked file with wrong lock, got %d", rec.Code)
	}
}

func TestRenameFile(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data:        []byte("content"),
		contentType: "application/octet-stream",
		etag:        "v1",
	}

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRenameFile)
	req.Header.Set(wopi.HeaderRequestedName, "renamed.docx")
	rec := httptest.NewRecorder()

	h.RenameFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["Name"] != "renamed.docx" {
		t.Errorf("expected Name %q, got %q", "renamed.docx", resp["Name"])
	}
}

func TestFilesHandler_Dispatch(t *testing.T) {
	h, _ := newTestHandler()

	tests := []struct {
		override string
		lockID   string
		wantCode int
	}{
		{wopi.OverrideLock, "lock-1", http.StatusOK},
		{wopi.OverrideGetLock, "", http.StatusOK},
		{"UNKNOWN_OVERRIDE", "", http.StatusNotImplemented},
	}

	for _, tt := range tests {
		req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
		req.Header.Set(wopi.HeaderOverride, tt.override)
		if tt.lockID != "" {
			req.Header.Set(wopi.HeaderLock, tt.lockID)
		}
		rec := httptest.NewRecorder()

		h.FilesHandler(rec, req)

		if rec.Code != tt.wantCode {
			t.Errorf("override %q: expected %d, got %d", tt.override, tt.wantCode, rec.Code)
		}
	}
}

func TestContentsHandler_GET(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data: []byte("content"),
		etag: "v1",
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/test.docx/contents", nil, "test.docx", "user1")
	rec := httptest.NewRecorder()

	h.ContentsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestContentsHandler_POST_PUT(t *testing.T) {
	h, _ := newTestHandler()

	// PutFile on non-existent file (zero bytes, allowed)
	content := []byte("new content")
	req := requestWithContext(http.MethodPost, "/wopi/files/new.docx/contents", bytes.NewReader(content), "new.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	req.ContentLength = int64(len(content))
	rec := httptest.NewRecorder()

	h.ContentsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestContentsHandler_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodDelete, "/wopi/files/test.docx/contents", nil, "test.docx", "user1")
	rec := httptest.NewRecorder()

	h.ContentsHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
