package wopi

import (
	"sync"
	"time"
)

// LockInfo holds metadata about a file lock.
type LockInfo struct {
	LockID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired returns true if the lock has passed its expiration time.
func (l *LockInfo) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// LockManager manages WOPI file locks.
// Locks automatically expire after the configured duration (default 30 minutes).
type LockManager struct {
	mu         sync.RWMutex
	locks      map[string]*LockInfo
	expiration time.Duration
}

// NewLockManager creates a new LockManager with the specified lock expiration duration.
func NewLockManager(expiration time.Duration) *LockManager {
	return &LockManager{
		locks:      make(map[string]*LockInfo),
		expiration: expiration,
	}
}

// Lock attempts to lock a file. If the file is already locked with a different
// lock ID, it returns the current lock ID and false. If the file is locked
// with the same lock ID, the lock is refreshed.
func (lm *LockManager) Lock(fileID, lockID string) (currentLockID string, ok bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	existing, exists := lm.locks[fileID]
	if exists && !existing.IsExpired() {
		if existing.LockID == lockID {
			// Same lock ID — treat as RefreshLock
			existing.ExpiresAt = time.Now().Add(lm.expiration)
			return lockID, true
		}
		// Different lock — conflict
		return existing.LockID, false
	}

	// File is unlocked or lock expired — create new lock
	lm.locks[fileID] = &LockInfo{
		LockID:    lockID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(lm.expiration),
	}
	return lockID, true
}

// GetLock returns the current lock ID for a file, or empty string if unlocked.
func (lm *LockManager) GetLock(fileID string) string {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	existing, exists := lm.locks[fileID]
	if !exists || existing.IsExpired() {
		return ""
	}
	return existing.LockID
}

// RefreshLock extends the lock expiration. Returns the current lock ID and false
// if the provided lock ID doesn't match.
func (lm *LockManager) RefreshLock(fileID, lockID string) (currentLockID string, ok bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	existing, exists := lm.locks[fileID]
	if !exists || existing.IsExpired() {
		return "", false
	}

	if existing.LockID != lockID {
		return existing.LockID, false
	}

	existing.ExpiresAt = time.Now().Add(lm.expiration)
	return lockID, true
}

// Unlock releases a lock. Returns the current lock ID and false if the provided
// lock ID doesn't match.
func (lm *LockManager) Unlock(fileID, lockID string) (currentLockID string, ok bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	existing, exists := lm.locks[fileID]
	if !exists || existing.IsExpired() {
		return "", false
	}

	if existing.LockID != lockID {
		return existing.LockID, false
	}

	delete(lm.locks, fileID)
	return "", true
}

// UnlockAndRelock atomically replaces a lock. Returns the current lock ID and
// false if the old lock ID doesn't match.
func (lm *LockManager) UnlockAndRelock(fileID, oldLockID, newLockID string) (currentLockID string, ok bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	existing, exists := lm.locks[fileID]
	if !exists || existing.IsExpired() {
		return "", false
	}

	if existing.LockID != oldLockID {
		return existing.LockID, false
	}

	lm.locks[fileID] = &LockInfo{
		LockID:    newLockID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(lm.expiration),
	}
	return newLockID, true
}

// ValidateLock checks if the provided lock ID matches the current lock on a file.
// Returns (currentLockID, true) if it matches or no lock exists. Returns
// (currentLockID, false) if there's a mismatch.
func (lm *LockManager) ValidateLock(fileID, lockID string) (currentLockID string, ok bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	existing, exists := lm.locks[fileID]
	if !exists || existing.IsExpired() {
		// No lock — valid only if no lock ID provided (empty files)
		return "", true
	}

	if existing.LockID == lockID {
		return lockID, true
	}

	return existing.LockID, false
}
