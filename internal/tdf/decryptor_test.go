package tdf

import "testing"

func TestIsTDFContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"tdf;application/vnd.openxmlformats-officedocument.wordprocessingml.document", true},
		{"tdf;application/pdf", true},
		{"tdf;", true},
		{"application/octet-stream", false},
		{"application/vnd.openxmlformats-officedocument.wordprocessingml.document", false},
		{"", false},
		{"TDF;application/pdf", false}, // case-sensitive
		{"text/plain", false},
		{"tdf", false}, // no semicolon
	}

	for _, tt := range tests {
		got := IsTDFContentType(tt.ct)
		if got != tt.want {
			t.Errorf("IsTDFContentType(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}
