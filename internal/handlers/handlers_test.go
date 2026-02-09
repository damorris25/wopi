package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/dmorris/wopi/internal/attrstore"
	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/tdf"
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
	m.objects[key] = &mockObject{data: data, contentType: ct, etag: etag, metadata: params.Metadata}
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

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(params.Prefix)
	delimiter := aws.ToString(params.Delimiter)

	var contents []s3types.Object
	var commonPrefixes []s3types.CommonPrefix

	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	seenPrefixes := make(map[string]bool)
	for _, key := range keys {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			idx := strings.Index(rest, delimiter)
			if idx >= 0 {
				cp := prefix + rest[:idx+len(delimiter)]
				if !seenPrefixes[cp] {
					seenPrefixes[cp] = true
					commonPrefixes = append(commonPrefixes, s3types.CommonPrefix{
						Prefix: aws.String(cp),
					})
				}
				continue
			}
		}
		obj := m.objects[key]
		size := int64(len(obj.data))
		now := time.Now()
		contents = append(contents, s3types.Object{
			Key:          aws.String(key),
			Size:         &size,
			LastModified: &now,
		})
	}
	return &s3.ListObjectsV2Output{
		Contents:       contents,
		CommonPrefixes: commonPrefixes,
		IsTruncated:    aws.Bool(false),
	}, nil
}

func newTestHandler() (*Handler, *mockS3Client) {
	mock := newMockS3Client()
	s3Store := storage.NewS3StorageWithClient(mock, "test-bucket")
	lockMgr := wopi.NewLockManager(30 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tv := middleware.NewTokenValidator("test-secret")

	h := &Handler{
		Storage:              s3Store,
		LockManager:          lockMgr,
		Logger:               logger,
		BaseURL:              "http://localhost:8080",
		WOPIClientURL:        "http://localhost:9980",
		WOPIClientEditorPath: "/browser/dist/cool.html",
		TokenValidator:       tv,
		AttrStore:            attrstore.New(),
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

func TestListFiles(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["docs/a.docx"] = &mockObject{data: []byte("aaa"), etag: "e1"}
	mock.objects["docs/b.xlsx"] = &mockObject{data: []byte("bb"), etag: "e2"}

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()

	h.ListFiles(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var items []storage.FileListItem
	if err := json.NewDecoder(rec.Body).Decode(&items); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestListFiles_Empty(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()

	h.ListFiles(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var items []storage.FileListItem
	if err := json.NewDecoder(rec.Body).Decode(&items); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
}

func TestGetEditorURL(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/editor?file_id=docs|test.docx", nil)
	rec := httptest.NewRecorder()

	h.GetEditorURL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	editorURL := resp["editor_url"]
	if editorURL == "" {
		t.Fatal("expected non-empty editor_url")
	}
	if !strings.Contains(editorURL, "http://localhost:9980/browser/dist/cool.html") {
		t.Errorf("expected Collabora URL prefix, got %q", editorURL)
	}
	if !strings.Contains(editorURL, "WOPISrc=") {
		t.Errorf("expected WOPISrc param, got %q", editorURL)
	}
	if !strings.Contains(editorURL, "access_token=") {
		t.Errorf("expected access_token param, got %q", editorURL)
	}
}

func TestGetEditorURL_MissingFileID(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/editor", nil)
	rec := httptest.NewRecorder()

	h.GetEditorURL(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetEditorURL_CustomClient(t *testing.T) {
	h, _ := newTestHandler()
	h.WOPIClientURL = "https://word-edit.officeapps.live.com"
	h.WOPIClientEditorPath = "/we/wordeditorframe.aspx"

	req := httptest.NewRequest(http.MethodGet, "/api/editor?file_id=report.docx", nil)
	rec := httptest.NewRecorder()

	h.GetEditorURL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	editorURL := resp["editor_url"]
	if !strings.Contains(editorURL, "https://word-edit.officeapps.live.com/we/wordeditorframe.aspx") {
		t.Errorf("expected custom client URL prefix, got %q", editorURL)
	}
	if !strings.Contains(editorURL, "WOPISrc=") {
		t.Errorf("expected WOPISrc param, got %q", editorURL)
	}
	if !strings.Contains(editorURL, "access_token=") {
		t.Errorf("expected access_token param, got %q", editorURL)
	}
}

func TestListFilesInFolder(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["docs/report.docx"] = &mockObject{data: []byte("a"), etag: "e1"}
	mock.objects["docs/sub/nested.txt"] = &mockObject{data: []byte("b"), etag: "e2"}
	mock.objects["images/photo.png"] = &mockObject{data: []byte("c"), etag: "e3"}

	req := httptest.NewRequest(http.MethodGet, "/api/files/browse?prefix=docs/", nil)
	rec := httptest.NewRecorder()

	h.ListFilesInFolder(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var listing storage.FolderListing
	if err := json.NewDecoder(rec.Body).Decode(&listing); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(listing.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(listing.Files))
	}
	if len(listing.Folders) != 1 {
		t.Errorf("expected 1 folder, got %d", len(listing.Folders))
	}
}

func TestUploadFile(t *testing.T) {
	h, mock := newTestHandler()

	// Build multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.docx")
	part.Write([]byte("file content"))
	writer.WriteField("prefix", "docs/")
	writer.WriteField("attributes", `["https://example.com/attr/a/value/v1"]`)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/files/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	h.UploadFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify file was stored
	if _, exists := mock.objects["docs/test.docx"]; !exists {
		t.Error("expected file to be stored at docs/test.docx")
	}

	// Verify metadata was set
	obj := mock.objects["docs/test.docx"]
	if obj.metadata == nil || obj.metadata["Tdf-Data-Attribute-0"] != "https://example.com/attr/a/value/v1" {
		t.Errorf("expected Tdf-Data-Attribute-0 metadata, got %v", obj.metadata)
	}

	// Verify attr store
	stored := h.AttrStore.Get("docs|test.docx")
	if len(stored) != 1 || stored[0] != "https://example.com/attr/a/value/v1" {
		t.Errorf("expected attr store entry, got %v", stored)
	}
}

func TestDeleteFileAPI(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{data: []byte("content"), etag: "v1"}
	h.AttrStore.Set("test.docx", []string{"attr1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/files?file_id=test.docx", nil)
	rec := httptest.NewRecorder()

	h.DeleteFileAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if _, exists := mock.objects["test.docx"]; exists {
		t.Error("expected file to be deleted")
	}
	if h.AttrStore.Get("test.docx") != nil {
		t.Error("expected attr store entry to be removed")
	}
}

func TestDeleteFileAPI_MissingParam(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodDelete, "/api/files", nil)
	rec := httptest.NewRecorder()

	h.DeleteFileAPI(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetAttributes_NoPlatform(t *testing.T) {
	h, _ := newTestHandler()
	// PlatformClient is nil by default

	req := httptest.NewRequest(http.MethodGet, "/api/attributes", nil)
	rec := httptest.NewRecorder()

	h.GetAttributes(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string][]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp["attributes"]) != 0 {
		t.Errorf("expected empty attributes, got %v", resp["attributes"])
	}
}

func TestPutFile_PreservesAttributes(t *testing.T) {
	h, mock := newTestHandler()

	// Pre-populate file and attr store (simulating a prior upload with attributes)
	mock.objects["test.docx"] = &mockObject{data: []byte("old"), etag: "v1"}
	h.AttrStore.Set("test.docx", []string{
		"https://example.com/attr/a/value/v1",
		"https://example.com/attr/b/value/v2",
	})

	h.LockManager.Lock("test.docx", "lock-123")

	newContent := []byte("new content from collabora")
	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx/contents", bytes.NewReader(newContent), "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePut)
	req.Header.Set(wopi.HeaderLock, "lock-123")
	req.ContentLength = int64(len(newContent))
	rec := httptest.NewRecorder()

	h.PutFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Verify that metadata was written
	obj := mock.objects["test.docx"]
	if obj.metadata == nil {
		t.Fatal("expected metadata to be set on save")
	}
	if obj.metadata["Tdf-Data-Attribute-0"] != "https://example.com/attr/a/value/v1" {
		t.Errorf("attr 0 mismatch: %v", obj.metadata)
	}
	if obj.metadata["Tdf-Data-Attribute-1"] != "https://example.com/attr/b/value/v2" {
		t.Errorf("attr 1 mismatch: %v", obj.metadata)
	}
}

// ---------------------------------------------------------------------------
// DownloadFile tests
// ---------------------------------------------------------------------------

func TestDownloadFile(t *testing.T) {
	h, mock := newTestHandler()

	content := []byte("download me")
	mock.objects["report.docx"] = &mockObject{
		data:        content,
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files/download?file_id=report.docx", nil)
	rec := httptest.NewRecorder()

	h.DownloadFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Errorf("body mismatch")
	}
	disp := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "report.docx") {
		t.Errorf("expected filename in Content-Disposition, got %q", disp)
	}
}

func TestDownloadFile_MissingFileID(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/files/download", nil)
	rec := httptest.NewRecorder()

	h.DownloadFile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDownloadFile_NotFound(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/files/download?file_id=missing.docx", nil)
	rec := httptest.NewRecorder()

	h.DownloadFile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDownloadFile_TDFBlocked(t *testing.T) {
	h, mock := newTestHandler()
	// Set a non-nil TDFDecryptor to enable TDF detection.
	// We can't easily construct a real Decryptor without an SDK, so we
	// verify the code path by checking the response when ContentType has
	// the tdf; prefix. The handler only checks tdf.IsTDFContentType and
	// the TDFDecryptor != nil guard.
	//
	// We use a minimal stub: create a mockDecryptor-carrying Handler.
	h.TDFDecryptor = &tdf.Decryptor{} // zero-value — only used for nil check

	mock.objects["secret.docx.tdf"] = &mockObject{
		data:        []byte("tdf-wrapped-content"),
		contentType: "tdf;application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files/download?file_id=secret.docx.tdf", nil)
	rec := httptest.NewRecorder()

	h.DownloadFile(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for TDF download, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDownloadFile_NonTDFWithDecryptorEnabled(t *testing.T) {
	h, mock := newTestHandler()
	h.TDFDecryptor = &tdf.Decryptor{} // non-nil but non-TDF file

	content := []byte("plain content")
	mock.objects["plain.docx"] = &mockObject{
		data:        content,
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files/download?file_id=plain.docx", nil)
	rec := httptest.NewRecorder()

	h.DownloadFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-TDF download, got %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Error("body mismatch for non-TDF download")
	}
}

// ---------------------------------------------------------------------------
// GetFileInfoAPI tests
// ---------------------------------------------------------------------------

func TestGetFileInfoAPI(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["docs/report.docx"] = &mockObject{
		data:        []byte("some content"),
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v42",
		metadata: map[string]string{
			"owner":                "alice",
			"tdf-data-attribute-0": "https://example.com/attr/a/value/v1",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files/info?file_id=docs|report.docx", nil)
	rec := httptest.NewRecorder()

	h.GetFileInfoAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["name"] != "report.docx" {
		t.Errorf("name = %v, want report.docx", resp["name"])
	}
	if resp["version"] != "v42" {
		t.Errorf("version = %v, want v42", resp["version"])
	}
	attrs, ok := resp["attributes"].([]interface{})
	if !ok || len(attrs) != 1 {
		t.Errorf("expected 1 attribute, got %v", resp["attributes"])
	}
}

func TestGetFileInfoAPI_MissingFileID(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/files/info", nil)
	rec := httptest.NewRecorder()

	h.GetFileInfoAPI(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetFileInfoAPI_NotFound(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/files/info?file_id=missing.docx", nil)
	rec := httptest.NewRecorder()

	h.GetFileInfoAPI(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// PutRelativeFile tests
// ---------------------------------------------------------------------------

func TestPutRelativeFile_RelativeTarget(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["original.docx"] = &mockObject{data: []byte("orig"), etag: "v1"}

	content := []byte("saved-as content")
	req := requestWithContext(http.MethodPost, "/wopi/files/original.docx", bytes.NewReader(content), "original.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePutRelative)
	req.Header.Set(wopi.HeaderRelativeTarget, "copy.docx")
	req.ContentLength = int64(len(content))
	rec := httptest.NewRecorder()

	h.PutRelativeFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["Name"] != "copy.docx" {
		t.Errorf("expected Name = copy.docx, got %v", resp["Name"])
	}
	if resp["Url"] == nil || resp["Url"] == "" {
		t.Error("expected non-empty Url in response")
	}

	if _, exists := mock.objects["copy.docx"]; !exists {
		t.Error("expected copy.docx to be stored")
	}
}

func TestPutRelativeFile_SuggestedTarget(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["original.docx"] = &mockObject{data: []byte("orig"), etag: "v1"}

	content := []byte("suggested content")
	req := requestWithContext(http.MethodPost, "/wopi/files/original.docx", bytes.NewReader(content), "original.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePutRelative)
	req.Header.Set(wopi.HeaderSuggestedTarget, "suggested.docx")
	req.ContentLength = int64(len(content))
	rec := httptest.NewRecorder()

	h.PutRelativeFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if _, exists := mock.objects["suggested.docx"]; !exists {
		t.Error("expected suggested.docx to be stored")
	}
}

func TestPutRelativeFile_MissingTarget(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/original.docx", bytes.NewReader([]byte("data")), "original.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverridePutRelative)
	// No target headers set
	rec := httptest.NewRecorder()

	h.PutRelativeFile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CheckFileInfo — TDF suffix stripping
// ---------------------------------------------------------------------------

func TestCheckFileInfo_TDFSuffix(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["report.docx.tdf"] = &mockObject{
		data:        []byte("encrypted data"),
		contentType: "tdf;application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
		metadata:    map[string]string{"owner": "alice"},
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/report.docx.tdf", nil, "report.docx.tdf", "user1")
	rec := httptest.NewRecorder()

	h.CheckFileInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp wopi.CheckFileInfoResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// The .tdf suffix should be stripped so Collabora sees .docx
	if resp.BaseFileName != "report.docx" {
		t.Errorf("expected BaseFileName %q, got %q", "report.docx", resp.BaseFileName)
	}
	// Size should be the actual (encrypted) size, not 0
	if resp.Size != 14 {
		t.Errorf("expected Size 14, got %d", resp.Size)
	}
}

// ---------------------------------------------------------------------------
// GetFile — TDF decryption path (integration with mock Decryptor)
// ---------------------------------------------------------------------------

// mockTDFDecryptor provides a fake decryptor for handler tests.
// Since tdf.Decryptor has unexported fields, we test the handler TDF
// branch by verifying the non-TDF guard (TDFDecryptor == nil → passthrough)
// and the TDF-blocked DownloadFile path (TDFDecryptor != nil + tdf; content).
// For the GetFile decrypt path, we verify it detects TDF content type
// correctly by testing with a nil decryptor (passthrough) and non-TDF content.

func TestGetFile_NonTDFPassthrough(t *testing.T) {
	h, mock := newTestHandler()
	// TDFDecryptor is nil — all files pass through unchanged
	content := []byte("plain office content")
	mock.objects["doc.docx"] = &mockObject{
		data:        content,
		contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/doc.docx/contents", nil, "doc.docx", "user1")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Error("expected passthrough content for non-TDF file")
	}
}

func TestGetFile_TDFContentWithNilDecryptor(t *testing.T) {
	h, mock := newTestHandler()
	// TDFDecryptor is nil — even TDF content passes through as-is
	content := []byte("tdf-container-bytes")
	mock.objects["secret.docx.tdf"] = &mockObject{
		data:        content,
		contentType: "tdf;application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/secret.docx.tdf/contents", nil, "secret.docx.tdf", "user1")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// With nil decryptor, raw TDF bytes pass through
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Error("expected raw TDF passthrough when decryptor is nil")
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestFileAttributeFQNs(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     []string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			want:     nil,
		},
		{
			name:     "empty metadata",
			metadata: map[string]string{},
			want:     nil,
		},
		{
			name: "single attribute",
			metadata: map[string]string{
				"tdf-data-attribute-0": "https://example.com/attr/a/value/v1",
			},
			want: []string{"https://example.com/attr/a/value/v1"},
		},
		{
			name: "multiple sequential attributes",
			metadata: map[string]string{
				"tdf-data-attribute-0": "https://example.com/attr/a/value/v1",
				"tdf-data-attribute-1": "https://example.com/attr/b/value/v2",
				"tdf-data-attribute-2": "https://example.com/attr/c/value/v3",
			},
			want: []string{
				"https://example.com/attr/a/value/v1",
				"https://example.com/attr/b/value/v2",
				"https://example.com/attr/c/value/v3",
			},
		},
		{
			name: "gap in numbering stops iteration",
			metadata: map[string]string{
				"tdf-data-attribute-0": "https://example.com/attr/a/value/v1",
				"tdf-data-attribute-2": "https://example.com/attr/c/value/v3",
			},
			want: []string{"https://example.com/attr/a/value/v1"},
		},
		{
			name: "unrelated metadata ignored",
			metadata: map[string]string{
				"owner":                "alice",
				"tdf-data-attribute-0": "https://example.com/attr/a/value/v1",
				"other-key":            "other-value",
			},
			want: []string{"https://example.com/attr/a/value/v1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fileAttributeFQNs(tt.metadata)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d FQNs, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("FQN[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildAttrMetadata(t *testing.T) {
	fqns := []string{
		"https://example.com/attr/a/value/v1",
		"https://example.com/attr/b/value/v2",
	}
	m := buildAttrMetadata(fqns)

	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["Tdf-Data-Attribute-0"] != fqns[0] {
		t.Errorf("entry 0 = %q, want %q", m["Tdf-Data-Attribute-0"], fqns[0])
	}
	if m["Tdf-Data-Attribute-1"] != fqns[1] {
		t.Errorf("entry 1 = %q, want %q", m["Tdf-Data-Attribute-1"], fqns[1])
	}
}

func TestBuildAttrMetadata_Empty(t *testing.T) {
	m := buildAttrMetadata(nil)
	if len(m) != 0 {
		t.Errorf("expected empty map for nil input, got %v", m)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"report.docx", "report.docx"},
		{"my report.docx", "my_report.docx"},
		{"hello (copy).docx", "hello_copy.docx"},
		{"café.txt", "caf.txt"},
		{"  ", "__"},                  // spaces become underscores, non-empty
		{".hidden", "upload.hidden"}, // empty name before ext → "upload"
		{"a/b/c.docx", "a/b/c.docx"},
		{"file with spaces & special!chars.pdf", "file_with_spaces__specialchars.pdf"},
	}

	for _, tt := range tests {
		got := sanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// GetEditorURL — WOPISrcBaseURL override
// ---------------------------------------------------------------------------

func TestGetEditorURL_WOPISrcBaseURL(t *testing.T) {
	h, _ := newTestHandler()
	h.WOPISrcBaseURL = "http://internal:8080"

	req := httptest.NewRequest(http.MethodGet, "/api/editor?file_id=test.docx", nil)
	rec := httptest.NewRecorder()

	h.GetEditorURL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)

	url := resp["editor_url"]
	// The WOPISrc should use the internal base URL, not the public one
	if !strings.Contains(url, "http%3A%2F%2Finternal%3A8080%2Fwopi%2Ffiles%2Ftest.docx") {
		t.Errorf("expected internal WOPISrc in URL, got %q", url)
	}
}

// ---------------------------------------------------------------------------
// Unlock and RefreshLock — missing header edge cases
// ---------------------------------------------------------------------------

func TestUnlock_MissingHeader(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideUnlock)
	// No X-WOPI-Lock header
	rec := httptest.NewRecorder()

	h.Unlock(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRefreshLock_MissingHeader(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRefreshLock)
	// No X-WOPI-Lock header
	rec := httptest.NewRecorder()

	h.RefreshLock(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestUnlockAndRelock_MissingHeaders(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideUnlockAndRelock)
	// No lock headers
	rec := httptest.NewRecorder()

	h.UnlockAndRelock(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RenameFile — error cases
// ---------------------------------------------------------------------------

func TestRenameFile_MissingName(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRenameFile)
	// No X-WOPI-RequestedName
	rec := httptest.NewRecorder()

	h.RenameFile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRenameFile_LockedWithWrongLock(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{data: []byte("content"), etag: "v1"}
	h.LockManager.Lock("test.docx", "lock-123")

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRenameFile)
	req.Header.Set(wopi.HeaderRequestedName, "newname.docx")
	req.Header.Set(wopi.HeaderLock, "wrong-lock")
	rec := httptest.NewRecorder()

	h.RenameFile(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestRenameFile_MigratesAttrStore(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data:        []byte("content"),
		contentType: "application/octet-stream",
		etag:        "v1",
	}
	h.AttrStore.Set("test.docx", []string{"https://example.com/attr/a/value/v1"})

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideRenameFile)
	req.Header.Set(wopi.HeaderRequestedName, "renamed.docx")
	rec := httptest.NewRecorder()

	h.RenameFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Old file ID should have no attrs
	if h.AttrStore.Get("test.docx") != nil {
		t.Error("expected old file ID attr store entry to be removed")
	}
	// New file ID should have the migrated attrs
	newAttrs := h.AttrStore.Get("renamed.docx")
	if len(newAttrs) != 1 || newAttrs[0] != "https://example.com/attr/a/value/v1" {
		t.Errorf("expected migrated attrs, got %v", newAttrs)
	}
}

// ---------------------------------------------------------------------------
// ContentsHandler — POST with unsupported override
// ---------------------------------------------------------------------------

func TestContentsHandler_POST_UnsupportedOverride(t *testing.T) {
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/test.docx/contents", nil, "test.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, "UNKNOWN")
	rec := httptest.NewRecorder()

	h.ContentsHandler(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// UploadFile — error cases
// ---------------------------------------------------------------------------

func TestUploadFile_MissingFile(t *testing.T) {
	h, _ := newTestHandler()

	// Multipart form without a "file" field
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("prefix", "docs/")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/files/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	h.UploadFile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadFile_InvalidAttributesJSON(t *testing.T) {
	h, _ := newTestHandler()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.docx")
	part.Write([]byte("file content"))
	writer.WriteField("attributes", "not-valid-json")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/files/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	h.UploadFile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteFile (WOPI) — not found
// ---------------------------------------------------------------------------

func TestDeleteFile_Succeeds_NonExistentKey(t *testing.T) {
	// S3 DeleteObject succeeds silently for non-existent keys, so the
	// WOPI handler returns 200 even when the key doesn't exist.
	h, _ := newTestHandler()

	req := requestWithContext(http.MethodPost, "/wopi/files/missing.docx", nil, "missing.docx", "user1")
	req.Header.Set(wopi.HeaderOverride, wopi.OverrideDelete)
	rec := httptest.NewRecorder()

	h.DeleteFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (S3 delete is idempotent), got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteFileAPI — cleans up attr store
// ---------------------------------------------------------------------------

func TestDeleteFileAPI_CleansAttrStore(t *testing.T) {
	h, mock := newTestHandler()
	mock.objects["test.docx"] = &mockObject{data: []byte("x"), etag: "v1"}
	h.AttrStore.Set("test.docx", []string{"attr1", "attr2"})

	req := httptest.NewRequest(http.MethodDelete, "/api/files?file_id=test.docx", nil)
	rec := httptest.NewRecorder()

	h.DeleteFileAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if h.AttrStore.Get("test.docx") != nil {
		t.Error("expected attr store entry to be removed after delete")
	}
}

// ---------------------------------------------------------------------------
// FilesHandler dispatch — all overrides
// ---------------------------------------------------------------------------

func TestFilesHandler_AllOverrides(t *testing.T) {
	// Verify that all known overrides dispatch without panicking
	overrides := []string{
		wopi.OverrideLock,
		wopi.OverrideGetLock,
		wopi.OverrideRefreshLock,
		wopi.OverrideUnlock,
		wopi.OverrideUnlockAndRelock,
		wopi.OverrideDelete,
		wopi.OverrideRenameFile,
		wopi.OverridePutRelative,
	}

	for _, ov := range overrides {
		t.Run(ov, func(t *testing.T) {
			h, mock := newTestHandler()
			mock.objects["test.docx"] = &mockObject{data: []byte("x"), etag: "v1", contentType: "application/octet-stream"}

			req := requestWithContext(http.MethodPost, "/wopi/files/test.docx", bytes.NewReader([]byte("body")), "test.docx", "user1")
			req.Header.Set(wopi.HeaderOverride, ov)
			req.Header.Set(wopi.HeaderLock, "lock-1")
			req.Header.Set(wopi.HeaderOldLock, "lock-1")
			req.Header.Set(wopi.HeaderRequestedName, "new.docx")
			req.Header.Set(wopi.HeaderSuggestedTarget, "target.docx")
			req.ContentLength = 4
			rec := httptest.NewRecorder()

			// Should not panic
			h.FilesHandler(rec, req)

			// All should return some valid HTTP status
			if rec.Code < 200 || rec.Code >= 600 {
				t.Errorf("%s: unexpected status %d", ov, rec.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetFile — version header absent when empty
// ---------------------------------------------------------------------------

func TestGetFile_NoVersionHeader(t *testing.T) {
	h, mock := newTestHandler()

	mock.objects["test.docx"] = &mockObject{
		data:        []byte("content"),
		contentType: "application/octet-stream",
		etag:        "", // empty etag
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/test.docx/contents", nil, "test.docx", "user1")
	rec := httptest.NewRecorder()

	h.GetFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if v := rec.Header().Get(wopi.HeaderItemVersion); v != "" {
		t.Errorf("expected empty version header for empty etag, got %q", v)
	}
}

// ---------------------------------------------------------------------------
// CheckFileInfo — size reflects encrypted size, not 0
// ---------------------------------------------------------------------------

func TestCheckFileInfo_TDFSizeNotZero(t *testing.T) {
	h, mock := newTestHandler()
	h.TDFDecryptor = &tdf.Decryptor{} // non-nil

	mock.objects["secret.docx.tdf"] = &mockObject{
		data:        make([]byte, 500000), // 500KB encrypted TDF
		contentType: "tdf;application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		etag:        "v1",
		metadata:    map[string]string{"owner": "system"},
	}

	req := requestWithContext(http.MethodGet, "/wopi/files/secret.docx.tdf", nil, "secret.docx.tdf", "user1")
	rec := httptest.NewRecorder()

	h.CheckFileInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp wopi.CheckFileInfoResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Size should be the actual encrypted size, NOT 0
	if resp.Size == 0 {
		t.Error("Size should not be 0 for TDF files — Collabora skips fetching empty files")
	}
	if resp.Size != 500000 {
		t.Errorf("expected Size 500000, got %d", resp.Size)
	}
	// Filename should have .tdf stripped
	if resp.BaseFileName != "secret.docx" {
		t.Errorf("expected BaseFileName %q, got %q", "secret.docx", resp.BaseFileName)
	}
}
