package wopi

import (
	"testing"
	"time"
)

func TestLockManager_Lock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// Lock a file
	lockID, ok := lm.Lock("file1", "lock-abc")
	if !ok {
		t.Fatal("expected lock to succeed")
	}
	if lockID != "lock-abc" {
		t.Fatalf("expected lock ID %q, got %q", "lock-abc", lockID)
	}

	// Same lock ID should succeed (treated as refresh)
	lockID, ok = lm.Lock("file1", "lock-abc")
	if !ok {
		t.Fatal("expected same lock ID to succeed as refresh")
	}

	// Different lock ID should fail
	lockID, ok = lm.Lock("file1", "lock-different")
	if ok {
		t.Fatal("expected different lock ID to fail")
	}
	if lockID != "lock-abc" {
		t.Fatalf("expected current lock %q, got %q", "lock-abc", lockID)
	}
}

func TestLockManager_GetLock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// No lock
	if got := lm.GetLock("file1"); got != "" {
		t.Fatalf("expected empty lock, got %q", got)
	}

	// After locking
	lm.Lock("file1", "lock-123")
	if got := lm.GetLock("file1"); got != "lock-123" {
		t.Fatalf("expected %q, got %q", "lock-123", got)
	}
}

func TestLockManager_RefreshLock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// Refresh non-existent lock
	_, ok := lm.RefreshLock("file1", "lock-123")
	if ok {
		t.Fatal("expected refresh of non-existent lock to fail")
	}

	// Lock then refresh with correct ID
	lm.Lock("file1", "lock-123")
	lockID, ok := lm.RefreshLock("file1", "lock-123")
	if !ok {
		t.Fatal("expected refresh to succeed")
	}
	if lockID != "lock-123" {
		t.Fatalf("expected %q, got %q", "lock-123", lockID)
	}

	// Refresh with wrong ID
	lockID, ok = lm.RefreshLock("file1", "wrong-lock")
	if ok {
		t.Fatal("expected refresh with wrong ID to fail")
	}
	if lockID != "lock-123" {
		t.Fatalf("expected current lock %q, got %q", "lock-123", lockID)
	}
}

func TestLockManager_Unlock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// Unlock non-existent lock
	_, ok := lm.Unlock("file1", "lock-123")
	if ok {
		t.Fatal("expected unlock of non-existent lock to fail")
	}

	// Lock then unlock with correct ID
	lm.Lock("file1", "lock-123")
	_, ok = lm.Unlock("file1", "lock-123")
	if !ok {
		t.Fatal("expected unlock to succeed")
	}

	// File should now be unlocked
	if got := lm.GetLock("file1"); got != "" {
		t.Fatalf("expected empty lock after unlock, got %q", got)
	}

	// Unlock with wrong ID
	lm.Lock("file1", "lock-456")
	lockID, ok := lm.Unlock("file1", "wrong-lock")
	if ok {
		t.Fatal("expected unlock with wrong ID to fail")
	}
	if lockID != "lock-456" {
		t.Fatalf("expected current lock %q, got %q", "lock-456", lockID)
	}
}

func TestLockManager_UnlockAndRelock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// Cannot unlock-and-relock non-existent lock
	_, ok := lm.UnlockAndRelock("file1", "old", "new")
	if ok {
		t.Fatal("expected failure on non-existent lock")
	}

	// Lock, then unlock-and-relock
	lm.Lock("file1", "lock-old")
	lockID, ok := lm.UnlockAndRelock("file1", "lock-old", "lock-new")
	if !ok {
		t.Fatal("expected unlock-and-relock to succeed")
	}
	if lockID != "lock-new" {
		t.Fatalf("expected %q, got %q", "lock-new", lockID)
	}

	// Verify new lock is in place
	if got := lm.GetLock("file1"); got != "lock-new" {
		t.Fatalf("expected %q, got %q", "lock-new", got)
	}

	// Wrong old lock ID should fail
	lockID, ok = lm.UnlockAndRelock("file1", "wrong-old", "lock-newer")
	if ok {
		t.Fatal("expected failure with wrong old lock")
	}
	if lockID != "lock-new" {
		t.Fatalf("expected current lock %q, got %q", "lock-new", lockID)
	}
}

func TestLockManager_Expiration(t *testing.T) {
	// Use a very short expiration
	lm := NewLockManager(1 * time.Millisecond)

	lm.Lock("file1", "lock-123")
	time.Sleep(5 * time.Millisecond)

	// Lock should have expired
	if got := lm.GetLock("file1"); got != "" {
		t.Fatalf("expected expired lock to return empty, got %q", got)
	}

	// Should be able to lock with new ID after expiry
	_, ok := lm.Lock("file1", "lock-new")
	if !ok {
		t.Fatal("expected lock to succeed after expiry")
	}
}

func TestLockManager_ValidateLock(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	// No lock — any validation passes
	_, ok := lm.ValidateLock("file1", "any-lock")
	if !ok {
		t.Fatal("expected validation to pass when no lock exists")
	}

	// With lock — matching ID passes
	lm.Lock("file1", "lock-123")
	_, ok = lm.ValidateLock("file1", "lock-123")
	if !ok {
		t.Fatal("expected matching lock to validate")
	}

	// With lock — mismatching ID fails
	currentLock, ok := lm.ValidateLock("file1", "wrong")
	if ok {
		t.Fatal("expected mismatching lock to fail validation")
	}
	if currentLock != "lock-123" {
		t.Fatalf("expected current lock %q, got %q", "lock-123", currentLock)
	}
}

func TestLockManager_MultipleFIles(t *testing.T) {
	lm := NewLockManager(30 * time.Minute)

	lm.Lock("file1", "lock-a")
	lm.Lock("file2", "lock-b")
	lm.Lock("file3", "lock-c")

	if got := lm.GetLock("file1"); got != "lock-a" {
		t.Fatalf("expected %q, got %q", "lock-a", got)
	}
	if got := lm.GetLock("file2"); got != "lock-b" {
		t.Fatalf("expected %q, got %q", "lock-b", got)
	}
	if got := lm.GetLock("file3"); got != "lock-c" {
		t.Fatalf("expected %q, got %q", "lock-c", got)
	}

	// Unlocking one doesn't affect others
	lm.Unlock("file2", "lock-b")
	if got := lm.GetLock("file1"); got != "lock-a" {
		t.Fatalf("expected %q after unlocking file2, got %q", "lock-a", got)
	}
	if got := lm.GetLock("file2"); got != "" {
		t.Fatalf("expected empty for unlocked file2, got %q", got)
	}
}
