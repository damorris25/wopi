package attrstore

import "sync"

// FileAttrStore is an in-memory concurrent-safe store that maps file IDs
// to their associated data attribute FQNs. When Collabora saves a file via
// WOPI PutFile, the handler looks up stored attributes here and re-supplies
// them as S3 metadata so the TDF proxy re-encrypts with the same attributes.
type FileAttrStore struct {
	mu    sync.RWMutex
	attrs map[string][]string
}

// New creates a new FileAttrStore.
func New() *FileAttrStore {
	return &FileAttrStore{
		attrs: make(map[string][]string),
	}
}

// Set stores the attribute FQNs for a file.
func (s *FileAttrStore) Set(fileID string, fqns []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs[fileID] = fqns
}

// Get returns the attribute FQNs for a file, or nil if not found.
func (s *FileAttrStore) Get(fileID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.attrs[fileID]
}

// Delete removes the attribute entry for a file.
func (s *FileAttrStore) Delete(fileID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attrs, fileID)
}
