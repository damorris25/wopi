package wopi

// CheckFileInfoResponse is the JSON response for the CheckFileInfo WOPI operation.
// See: https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/checkfileinfo/checkfileinfo-response
type CheckFileInfoResponse struct {
	// Required properties
	BaseFileName string `json:"BaseFileName"`
	OwnerId      string `json:"OwnerId"`
	Size         int64  `json:"Size"`
	UserId       string `json:"UserId"`
	Version      string `json:"Version"`

	// Host capabilities
	SupportsDeleteFile        bool `json:"SupportsDeleteFile,omitempty"`
	SupportsExtendedLockLength bool `json:"SupportsExtendedLockLength,omitempty"`
	SupportsGetLock           bool `json:"SupportsGetLock,omitempty"`
	SupportsLocks             bool `json:"SupportsLocks,omitempty"`
	SupportsRename            bool `json:"SupportsRename,omitempty"`
	SupportsUpdate            bool `json:"SupportsUpdate,omitempty"`

	// User metadata
	IsAnonymousUser  bool   `json:"IsAnonymousUser,omitempty"`
	UserFriendlyName string `json:"UserFriendlyName,omitempty"`

	// User permissions
	ReadOnly     bool `json:"ReadOnly,omitempty"`
	UserCanWrite bool `json:"UserCanWrite,omitempty"`
	UserCanRename bool `json:"UserCanRename,omitempty"`
	UserCanNotWriteRelative bool `json:"UserCanNotWriteRelative,omitempty"`

	// Collabora-specific restrictions (set by obligation enforcement)
	DisableCopy   bool `json:"DisableCopy,omitempty"`
	DisablePrint  bool `json:"DisablePrint,omitempty"`
	DisableExport bool `json:"DisableExport,omitempty"`

	// File URLs
	CloseUrl    string `json:"CloseUrl,omitempty"`
	DownloadUrl string `json:"DownloadUrl,omitempty"`
	HostEditUrl string `json:"HostEditUrl,omitempty"`
	HostViewUrl string `json:"HostViewUrl,omitempty"`
}

// WOPI override header values.
const (
	OverrideLock           = "LOCK"
	OverrideGetLock        = "GET_LOCK"
	OverrideRefreshLock    = "REFRESH_LOCK"
	OverrideUnlock         = "UNLOCK"
	OverrideUnlockAndRelock = "UNLOCK_AND_RELOCK"
	OverridePut            = "PUT"
	OverrideDelete         = "DELETE"
	OverrideRenameFile     = "RENAME_FILE"
	OverridePutRelative    = "PUT_RELATIVE"
)

// WOPI header names.
const (
	HeaderOverride           = "X-WOPI-Override"
	HeaderLock               = "X-WOPI-Lock"
	HeaderOldLock            = "X-WOPI-OldLock"
	HeaderLockFailureReason  = "X-WOPI-LockFailureReason"
	HeaderItemVersion        = "X-WOPI-ItemVersion"
	HeaderMaxExpectedSize    = "X-WOPI-MaxExpectedSize"
	HeaderRequestedName      = "X-WOPI-RequestedName"
	HeaderRelativeTarget     = "X-WOPI-RelativeTarget"
	HeaderOverwriteRelative  = "X-WOPI-OverwriteRelativeTarget"
	HeaderSuggestedTarget    = "X-WOPI-SuggestedTarget"
	HeaderEditors            = "X-WOPI-Editors"
)
