package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/wopi"
)

// Handler holds dependencies for WOPI request handlers.
type Handler struct {
	Storage     *storage.S3Storage
	LockManager *wopi.LockManager
	Logger      *slog.Logger
	BaseURL     string
}

// CheckFileInfo handles GET /wopi/files/{file_id}
func (h *Handler) CheckFileInfo(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
	userID := r.Context().Value(middleware.UserIDKey).(string)

	info, err := h.Storage.GetFileInfo(r.Context(), fileID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		h.Logger.Error("CheckFileInfo failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := wopi.CheckFileInfoResponse{
		BaseFileName: info.Name,
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.Logger.Error("failed to encode CheckFileInfo response", "error", err)
	}
}

// GetFile handles GET /wopi/files/{file_id}/contents
func (h *Handler) GetFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)

	// Check X-WOPI-MaxExpectedSize
	if maxSizeStr := r.Header.Get(wopi.HeaderMaxExpectedSize); maxSizeStr != "" {
		maxSize, err := strconv.ParseInt(maxSizeStr, 10, 64)
		if err == nil {
			info, err := h.Storage.GetFileInfo(r.Context(), fileID)
			if err == nil && info.Size > maxSize {
				http.Error(w, "file too large", http.StatusPreconditionFailed)
				return
			}
		}
	}

	body, info, err := h.Storage.GetFile(r.Context(), fileID)
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

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, body); err != nil {
		h.Logger.Error("error streaming file", "error", err, "file_id", fileID)
	}
}

// PutFile handles POST /wopi/files/{file_id}/contents (X-WOPI-Override: PUT)
func (h *Handler) PutFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)
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
		info, err := h.Storage.GetFileInfo(r.Context(), fileID)
		if err == nil && info.Size > 0 {
			w.Header().Set(wopi.HeaderLock, "")
			w.WriteHeader(http.StatusConflict)
			return
		}
		// File doesn't exist or is empty — allow PutFile (document creation)
	}

	version, err := h.Storage.PutFile(r.Context(), fileID, r.Body, r.ContentLength)
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
	fileID := r.Context().Value(middleware.FileIDKey).(string)

	// Check lock
	currentLock := h.LockManager.GetLock(fileID)
	lockID := r.Header.Get(wopi.HeaderLock)
	if currentLock != "" && lockID != currentLock {
		w.Header().Set(wopi.HeaderLock, currentLock)
		w.WriteHeader(http.StatusConflict)
		return
	}

	if err := h.Storage.DeleteFile(r.Context(), fileID); err != nil {
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
	fileID := r.Context().Value(middleware.FileIDKey).(string)
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

	newFileID, err := h.Storage.RenameFile(r.Context(), fileID, requestedName)
	if err != nil {
		h.Logger.Error("RenameFile failed", "error", err, "file_id", fileID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"Name": requestedName}
	_ = newFileID // New file ID is communicated via Name in response

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// PutRelativeFile handles the PUT_RELATIVE operation.
func (h *Handler) PutRelativeFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.Context().Value(middleware.FileIDKey).(string)

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

	version, err := h.Storage.PutFile(r.Context(), newFileID, r.Body, r.ContentLength)
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
