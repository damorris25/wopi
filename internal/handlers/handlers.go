package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/dmorris/wopi/internal/attrstore"
	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/platform"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/tdf"
	"github.com/dmorris/wopi/internal/wopi"
)

// Handler holds dependencies for WOPI request handlers.
type Handler struct {
	Storage        *storage.S3Storage
	LockManager    *wopi.LockManager
	Logger         *slog.Logger
	BaseURL              string
	WOPIClientURL        string
	WOPIClientEditorPath string
	WOPISrcBaseURL       string // Base URL for WOPISrc in Collabora callbacks (defaults to BaseURL)
	TokenValidator *middleware.TokenValidator
	PlatformClient *platform.Client        // for entitlements lookups (nil when not configured)
	AttrStore      *attrstore.FileAttrStore // fileID → attribute FQNs
	TokenStore     *middleware.TokenStore   // per-user OAuth2 tokens for S3 auth (nil when not configured)
	TDFDecryptor   *tdf.Decryptor          // client-side TDF decryption (nil when not configured)
}

// withUserToken injects the user's bearer token into the context so that
// BearerTokenTransport uses it instead of the service-account token.
// It checks the OIDC access token (API routes) first, then falls back to
// the TokenStore (WOPI routes).
func (h *Handler) withUserToken(ctx context.Context) context.Context {
	// 1. Check OIDC context token (set by Protect middleware for API routes).
	if token, ok := ctx.Value(middleware.OIDCAccessTokenKey).(string); ok && token != "" {
		h.Logger.Debug("using OIDC user token for S3 request")
		return storage.WithBearerToken(ctx, token)
	}
	// 2. Check TokenStore (WOPI routes — keyed by userID:fileID).
	if h.TokenStore != nil {
		userID, _ := ctx.Value(middleware.UserIDKey).(string)
		fileID, _ := ctx.Value(middleware.FileIDKey).(string)
		if userID != "" && fileID != "" {
			key := middleware.TokenStoreKey(userID, fileID)
			if token, ok := h.TokenStore.GetToken(ctx, key); ok {
				h.Logger.Debug("using WOPI session token for S3 request", "key", key)
				return storage.WithBearerToken(ctx, token)
			}
			h.Logger.Debug("no WOPI session token found", "key", key)
		}
	}
	h.Logger.Debug("using service account token for S3 request (fallback)")
	return ctx // fallback: service account
}

// fileAttributeFQNs extracts TDF data attribute FQNs from S3 object metadata.
func fileAttributeFQNs(metadata map[string]string) []string {
	if metadata == nil {
		return nil
	}
	var fqns []string
	for i := 0; ; i++ {
		key := fmt.Sprintf("tdf-data-attribute-%d", i)
		val, ok := metadata[key]
		if !ok {
			break
		}
		fqns = append(fqns, val)
	}
	return fqns
}

// getObligations resolves obligations for a file. It reads the file's S3
// metadata to get attribute FQNs, then queries the platform for obligation
// triggers matching those attributes.
func (h *Handler) getObligations(ctx context.Context, fileID string) (*platform.ObligationSet, error) {
	if h.PlatformClient == nil {
		return &platform.ObligationSet{}, nil
	}
	info, err := h.Storage.GetFileInfo(ctx, fileID)
	if err != nil {
		return nil, err
	}
	attrFQNs := fileAttributeFQNs(info.Metadata)
	if len(attrFQNs) == 0 {
		return &platform.ObligationSet{}, nil
	}
	return h.PlatformClient.GetObligations(ctx, attrFQNs)
}

// CheckFileInfo handles GET /wopi/files/{file_id}
func (h *Handler) CheckFileInfo(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)
	userID := ctx.Value(middleware.UserIDKey).(string)

	info, err := h.Storage.GetFileInfo(ctx, fileID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("CheckFileInfo failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Strip .tdf suffix so Collabora sees the underlying Office extension
	// (e.g. ".docx.tdf" → ".docx"). The s4proxy transparently decrypts the
	// TDF wrapper, so the content Collabora receives is the raw Office file.
	baseName := info.Name
	if strings.HasSuffix(strings.ToLower(baseName), ".tdf") {
		baseName = baseName[:len(baseName)-4]
	}

	resp := wopi.CheckFileInfoResponse{
		BaseFileName: baseName,
		OwnerId:      info.Owner,
		Size:         info.Size,
		UserId:       userID,
		Version:      info.Version,

		SupportsDeleteFile:         true,
		SupportsExtendedLockLength: true,
		SupportsGetLock:            true,
		SupportsLocks:              true,
		SupportsRename:             true,
		SupportsUpdate:             true,

		UserCanWrite:  true,
		UserCanRename: true,

		UserFriendlyName: userID,
	}

	// Apply obligation-based restrictions from the platform.
	attrFQNs := fileAttributeFQNs(info.Metadata)
	if h.PlatformClient != nil && len(attrFQNs) > 0 {
		obligations, err := h.PlatformClient.GetObligations(ctx, attrFQNs)
		if err != nil {
			h.Logger.Error("failed to resolve obligations", "error", err, "file_id", fileID)
		} else {
			if obligations.NoCopy {
				resp.DisableCopy = true
			}
			if obligations.NoPrint {
				resp.DisablePrint = true
			}
			if obligations.NoDownload {
				resp.DisableExport = true
			}
			if obligations.NoCopy || obligations.NoPrint || obligations.NoDownload {
				h.Logger.Info("obligations enforced",
					"file_id", fileID,
					"no_copy", obligations.NoCopy,
					"no_print", obligations.NoPrint,
					"no_download", obligations.NoDownload,
				)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.Logger.Error("failed to encode CheckFileInfo response", "error", err)
	}
}

// GetFile handles GET /wopi/files/{file_id}/contents
func (h *Handler) GetFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)

	// Check X-WOPI-MaxExpectedSize
	if maxSizeStr := r.Header.Get(wopi.HeaderMaxExpectedSize); maxSizeStr != "" {
		maxSize, err := strconv.ParseInt(maxSizeStr, 10, 64)
		if err == nil {
			info, err := h.Storage.GetFileInfo(ctx, fileID)
			if err == nil && info.Size > maxSize {
				http.Error(w, "file too large", http.StatusPreconditionFailed)
				return
			}
		}
	}

	body, info, err := h.Storage.GetFile(ctx, fileID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("GetFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer body.Close()

	if info.Version != "" {
		w.Header().Set(wopi.HeaderItemVersion, info.Version)
	}

	// If the file is still TDF-wrapped (s4proxy didn't decrypt it due to
	// unfulfillable obligations), decrypt it here using the OpenTDF SDK.
	if h.TDFDecryptor != nil && tdf.IsTDFContentType(info.ContentType) {
		plaintext, decErr := h.TDFDecryptor.Decrypt(ctx, body)
		if decErr != nil {
			h.Logger.Error("TDF decryption failed", "error", decErr, "file_id", fileID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(int64(len(plaintext)), 10))
		if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
			h.Logger.Error("error streaming decrypted file", "error", err, "file_id", fileID)
		}
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, body); err != nil {
		h.Logger.Error("error streaming file", "error", err, "file_id", fileID)
	}
}

// PutFile handles POST /wopi/files/{file_id}/contents (X-WOPI-Override: PUT)
func (h *Handler) PutFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)
	lockID := r.Header.Get(wopi.HeaderLock)

	// Check lock state
	currentLock := h.LockManager.GetLock(fileID)
	if currentLock != "" {
		// File is locked — lock ID must match
		if lockID != currentLock {
			w.Header().Set(wopi.HeaderLock, currentLock)
			w.Header().Set(wopi.HeaderLockFailureReason, "lock mismatch")
			w.WriteHeader(http.StatusConflict)
			return
		}
	} else if lockID == "" {
		// File is unlocked and no lock provided — only valid for zero-byte files
		info, err := h.Storage.GetFileInfo(ctx, fileID)
		if err == nil && info.Size > 0 {
			w.Header().Set(wopi.HeaderLock, "")
			w.WriteHeader(http.StatusConflict)
			return
		}
		// File doesn't exist or is empty — allow PutFile (document creation)
	}

	// Check if this file has stored data attributes (from a prior upload).
	// If so, re-supply them as S3 metadata so the TDF proxy re-encrypts
	// with the same attributes.
	var version string
	if h.AttrStore != nil {
		if fqns := h.AttrStore.Get(fileID); len(fqns) > 0 {
			metadata := buildAttrMetadata(fqns)
			var putErr error
			version, putErr = h.Storage.PutFileWithMetadata(ctx, fileID, r.Body, r.ContentLength, metadata)
			if putErr != nil {
				h.Logger.Error("PutFile (with attrs) failed", "error", putErr, "file_id", fileID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if version != "" {
				w.Header().Set(wopi.HeaderItemVersion, version)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	var err error
	version, err = h.Storage.PutFile(ctx, fileID, r.Body, r.ContentLength)
	if err != nil {
		h.Logger.Error("PutFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if version != "" {
		w.Header().Set(wopi.HeaderItemVersion, version)
	}
	w.WriteHeader(http.StatusOK)
}

// FilesHandler dispatches POST /wopi/files/{file_id} based on X-WOPI-Override.
func (h *Handler) FilesHandler(w http.ResponseWriter, r *http.Request) {
	override := r.Header.Get(wopi.HeaderOverride)

	switch override {
	case wopi.OverrideLock:
		h.Lock(w, r)
	case wopi.OverrideGetLock:
		h.GetLock(w, r)
	case wopi.OverrideRefreshLock:
		h.RefreshLock(w, r)
	case wopi.OverrideUnlock:
		h.Unlock(w, r)
	case wopi.OverrideUnlockAndRelock:
		h.UnlockAndRelock(w, r)
	case wopi.OverrideDelete:
		h.DeleteFile(w, r)
	case wopi.OverrideRenameFile:
		h.RenameFile(w, r)
	case wopi.OverridePutRelative:
		h.PutRelativeFile(w, r)
	default:
		http.Error(w, "unsupported override: "+override, http.StatusNotImplemented)
	}
}

// ContentsHandler dispatches requests to /wopi/files/{file_id}/contents.
func (h *Handler) ContentsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.GetFile(w, r)
	case http.MethodPost:
		override := r.Header.Get(wopi.HeaderOverride)
		if override == wopi.OverridePut {
			h.PutFile(w, r)
		} else {
			http.Error(w, "unsupported override for contents: "+override, http.StatusNotImplemented)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// Lock handles the LOCK operation.
func (h *Handler) Lock(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
	lockID := r.Header.Get(wopi.HeaderLock)

	if lockID == "" {
		http.Error(w, "missing X-WOPI-Lock header", http.StatusBadRequest)
		return
	}

	currentLock, ok := h.LockManager.Lock(fileID, lockID)
	if !ok {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.Header().Set(wopi.HeaderLockFailureReason, "file already locked with different lock ID")
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// GetLock handles the GET_LOCK operation.
func (h *Handler) GetLock(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)

	lockID := h.LockManager.GetLock(fileID)
	w.Header().Set(wopi.HeaderLock, lockID)
	w.WriteHeader(http.StatusOK)
}

// RefreshLock handles the REFRESH_LOCK operation.
func (h *Handler) RefreshLock(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
	lockID := r.Header.Get(wopi.HeaderLock)

	if lockID == "" {
		http.Error(w, "missing X-WOPI-Lock header", http.StatusBadRequest)
		return
	}

	currentLock, ok := h.LockManager.RefreshLock(fileID, lockID)
	if !ok {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.Header().Set(wopi.HeaderLockFailureReason, "lock mismatch or file not locked")
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Unlock handles the UNLOCK operation.
func (h *Handler) Unlock(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
	lockID := r.Header.Get(wopi.HeaderLock)

	if lockID == "" {
		http.Error(w, "missing X-WOPI-Lock header", http.StatusBadRequest)
		return
	}

	currentLock, ok := h.LockManager.Unlock(fileID, lockID)
	if !ok {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.Header().Set(wopi.HeaderLockFailureReason, "lock mismatch")
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// UnlockAndRelock handles the UNLOCK_AND_RELOCK operation.
func (h *Handler) UnlockAndRelock(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
	newLockID := r.Header.Get(wopi.HeaderLock)
	oldLockID := r.Header.Get(wopi.HeaderOldLock)

	if newLockID == "" || oldLockID == "" {
		http.Error(w, "missing X-WOPI-Lock or X-WOPI-OldLock header", http.StatusBadRequest)
		return
	}

	currentLock, ok := h.LockManager.UnlockAndRelock(fileID, oldLockID, newLockID)
	if !ok {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.Header().Set(wopi.HeaderLockFailureReason, "lock mismatch")
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteFile handles the DELETE operation.
func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)

	// Check lock
	currentLock := h.LockManager.GetLock(fileID)
	lockID := r.Header.Get(wopi.HeaderLock)
	if currentLock != "" && lockID != currentLock {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.WriteHeader(http.StatusConflict)
		return
	}

	if err := h.Storage.DeleteFile(ctx, fileID); err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("DeleteFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RenameFile handles the RENAME_FILE operation.
func (h *Handler) RenameFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)
	lockID := r.Header.Get(wopi.HeaderLock)
	requestedName := r.Header.Get(wopi.HeaderRequestedName)

	if requestedName == "" {
		http.Error(w, "missing X-WOPI-RequestedName header", http.StatusBadRequest)
		return
	}

	// Check lock
	currentLock := h.LockManager.GetLock(fileID)
	if currentLock != "" && lockID != currentLock {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.WriteHeader(http.StatusConflict)
		return
	}

	newFileID, err := h.Storage.RenameFile(ctx, fileID, requestedName)
	if err != nil {
		h.Logger.Error("RenameFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Migrate attribute store entry from old to new file ID.
	if h.AttrStore != nil {
		if fqns := h.AttrStore.Get(fileID); len(fqns) > 0 {
			h.AttrStore.Set(newFileID, fqns)
			h.AttrStore.Delete(fileID)
		}
	}

	resp := map[string]string{"Name": requestedName}
	_ = newFileID // New file ID is communicated via Name in response

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListFiles handles GET /api/files — returns a JSON list of files in the bucket.
func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	prefix := r.URL.Query().Get("prefix")
	items, err := h.Storage.ListFiles(ctx, prefix)
	if err != nil {
		h.Logger.Error("ListFiles failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []storage.FileListItem{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// GetEditorURL handles GET /api/editor — returns the WOPI client editor URL for a file.
func (h *Handler) GetEditorURL(w http.ResponseWriter, r *http.Request) {
	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		http.Error(w, "file_id required", http.StatusBadRequest)
		return
	}

	userID := "anonymous"
	if uid, ok := r.Context().Value(middleware.OIDCUserIDKey).(string); ok && uid != "" {
		userID = uid
	}

	// Stash user's OAuth2 token for later WOPI callbacks from Collabora.
	// Copy the full token entry (including refresh token) from the user's
	// primary entry (keyed by userID) to a WOPI-session entry (keyed by
	// userID:fileID) so the WOPI callbacks can use it.
	if h.TokenStore != nil && userID != "anonymous" {
		key := middleware.TokenStoreKey(userID, fileID)
		if entry := h.TokenStore.GetEntry(userID); entry != nil {
			h.TokenStore.Store(key, entry)
		}
	}

	token := h.TokenValidator.GenerateToken(userID, fileID)

	wopiBase := h.BaseURL
	if h.WOPISrcBaseURL != "" {
		wopiBase = h.WOPISrcBaseURL
	}
	wopiSrc := fmt.Sprintf("%s/wopi/files/%s", wopiBase, fileID)
	editorURL := fmt.Sprintf("%s%s?WOPISrc=%s&access_token=%s",
		h.WOPIClientURL,
		h.WOPIClientEditorPath,
		url.QueryEscape(wopiSrc),
		url.QueryEscape(token),
	)

	h.Logger.Info("editor URL generated", "file_id", fileID, "user_id", userID, "wopi_src", wopiSrc, "editor_url", editorURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"editor_url": editorURL})
}

// PutRelativeFile handles the PUT_RELATIVE operation.
func (h *Handler) PutRelativeFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := ctx.Value(middleware.FileIDKey).(string)

	suggestedTarget := r.Header.Get(wopi.HeaderSuggestedTarget)
	relativeTarget := r.Header.Get(wopi.HeaderRelativeTarget)

	var targetName string
	if relativeTarget != "" {
		targetName = relativeTarget
	} else if suggestedTarget != "" {
		targetName = suggestedTarget
	} else {
		http.Error(w, "missing target header", http.StatusBadRequest)
		return
	}

	// Derive new file ID from current file's directory + target name
	_ = fileID
	newFileID := targetName // Simplified: use target name as new file ID

	version, err := h.Storage.PutFile(ctx, newFileID, r.Body, r.ContentLength)
	if err != nil {
		h.Logger.Error("PutRelativeFile failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"Name": targetName,
		"Url":  h.BaseURL + "/wopi/files/" + newFileID,
	}
	_ = version

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListFilesInFolder handles GET /api/files/browse — returns files and subfolders at a prefix.
func (h *Handler) ListFilesInFolder(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	prefix := r.URL.Query().Get("prefix")
	listing, err := h.Storage.ListFilesInFolder(ctx, prefix)
	if err != nil {
		h.Logger.Error("ListFilesInFolder failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listing)
}

// UploadFile handles POST /api/files/upload — accepts multipart form with file, prefix, and attributes.
func (h *Handler) UploadFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	if err := r.ParseMultipartForm(64 << 20); err != nil { // 64 MB max
		http.Error(w, "failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	prefix := r.FormValue("prefix")
	fileKey := prefix + sanitizeFilename(header.Filename)

	// Parse optional attributes JSON array.
	var attrs []string
	if attrJSON := r.FormValue("attributes"); attrJSON != "" {
		if err := json.Unmarshal([]byte(attrJSON), &attrs); err != nil {
			http.Error(w, "invalid attributes JSON", http.StatusBadRequest)
			return
		}
	}

	var metadata map[string]string
	if len(attrs) > 0 {
		metadata = buildAttrMetadata(attrs)
	}

	// Use pipe-separated file ID for storage.
	storageFileID := storage.KeyToFileID(fileKey)

	version, err := h.Storage.PutFileWithMetadata(ctx, storageFileID, file, header.Size, metadata)
	if err != nil {
		h.Logger.Error("UploadFile failed", "error", err, "file_id", fileKey)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store attributes for future saves.
	if h.AttrStore != nil && len(attrs) > 0 {
		h.AttrStore.Set(storageFileID, attrs)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"file_id": storageFileID,
		"version": version,
	})
}

// DeleteFileAPI handles DELETE /api/files — deletes a file by file_id query param.
func (h *Handler) DeleteFileAPI(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		http.Error(w, "file_id required", http.StatusBadRequest)
		return
	}

	if err := h.Storage.DeleteFile(ctx, fileID); err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("DeleteFileAPI failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if h.AttrStore != nil {
		h.AttrStore.Delete(fileID)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// GetAttributes handles GET /api/attributes — returns available attribute values from the platform.
func (h *Handler) GetAttributes(w http.ResponseWriter, r *http.Request) {
	if h.PlatformClient == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]string{"attributes": {}})
		return
	}

	attrs, err := h.PlatformClient.ListAttributeValues(r.Context())
	if err != nil {
		h.Logger.Error("GetAttributes failed", "error", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]string{"attributes": {}})
		return
	}

	if attrs == nil {
		attrs = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"attributes": attrs})
}

// DownloadFile handles GET /api/files/download — streams the file as an attachment.
func (h *Handler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		http.Error(w, "file_id required", http.StatusBadRequest)
		return
	}

	body, info, err := h.Storage.GetFile(ctx, fileID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("DownloadFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer body.Close()

	// Block direct download for obligation-protected TDF files — these
	// must be viewed in the editor where obligations are enforced.
	if h.TDFDecryptor != nil && tdf.IsTDFContentType(info.ContentType) {
		http.Error(w, "this file can only be viewed in the editor", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.Name))
	if info.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	}
	if _, err := io.Copy(w, body); err != nil {
		h.Logger.Error("error streaming download", "error", err, "file_id", fileID)
	}
}

// GetFileInfoAPI handles GET /api/files/info — returns file metadata and attributes.
func (h *Handler) GetFileInfoAPI(w http.ResponseWriter, r *http.Request) {
	ctx := h.withUserToken(r.Context())
	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		http.Error(w, "file_id required", http.StatusBadRequest)
		return
	}

	info, err := h.Storage.GetFileInfo(ctx, fileID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("GetFileInfoAPI failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Extract TDF data attributes from S3 object metadata.
	attrs := fileAttributeFQNs(info.Metadata)
	if attrs == nil {
		attrs = []string{}
	}

	resp := map[string]interface{}{
		"file_id":       fileID,
		"name":          info.Name,
		"size":          info.Size,
		"last_modified": info.LastModified,
		"content_type":  info.ContentType,
		"version":       info.Version,
		"attributes":    attrs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// buildAttrMetadata converts a slice of attribute FQNs into S3 metadata
// with keys Tdf-Data-Attribute-0, Tdf-Data-Attribute-1, etc.
func buildAttrMetadata(fqns []string) map[string]string {
	m := make(map[string]string, len(fqns))
	for i, fqn := range fqns {
		m[fmt.Sprintf("Tdf-Data-Attribute-%d", i)] = fqn
	}
	return m
}

// unsafeCharsRe matches characters that are not safe in S3 object keys
// when processed through proxies like s4proxy (which can choke on spaces,
// commas, and other special characters in URL paths).
var unsafeCharsRe = regexp.MustCompile(`[^a-zA-Z0-9._\-/]`)

// sanitizeFilename replaces spaces with underscores and removes characters
// that are known to cause issues with the Secure Object Proxy.
// The file extension is preserved.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	ext := ""
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		ext = name[dot:]
		name = name[:dot]
	}
	name = unsafeCharsRe.ReplaceAllString(name, "")
	if name == "" {
		name = "upload"
	}
	return name + ext
}
