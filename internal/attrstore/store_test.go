package attrstore

import (
	"sync"
	"testing"
)

func TestSetGetRoundTrip(t *testing.T) {
	s := New()
	fqns := []string{"https://example.com/attr/a/value/v1", "https://example.com/attr/b/value/v2"}
	s.Set("file1", fqns)

	got := s.Get("file1")
	if len(got) != 2 {
		t.Fatalf("expected 2 FQNs, got %d", len(got))
	}
	if got[0] != fqns[0] || got[1] != fqns[1] {
		t.Errorf("FQN mismatch: got %v, want %v", got, fqns)
	}
}

func TestGetMissing(t *testing.T) {
	s := New()
	got := s.Get("nonexistent")
	if got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestDeleteRemovesEntry(t *testing.T) {
	s := New()
	s.Set("file1", []string{"attr1"})
	s.Delete("file1")

	got := s.Get("file1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "file"
			s.Set(key, []string{"attr"})
			_ = s.Get(key)
			s.Delete(key)
		}(i)
	}

	wg.Wait()
}
