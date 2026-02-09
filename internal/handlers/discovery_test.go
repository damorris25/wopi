package handlers

import (
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscovery_ReturnsXML(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://collabora.example.com",
		WOPIClientEditorPath: "/browser/dist/cool.html",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Errorf("expected application/xml content type, got %q", ct)
	}

	// Verify the response is valid XML.
	var discovery WOPIDiscovery
	if err := xml.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("failed to parse discovery XML: %v", err)
	}
}

func TestDiscovery_ContainsExpectedApps(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://collabora.example.com",
		WOPIClientEditorPath: "/browser/dist/cool.html",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	var discovery WOPIDiscovery
	if err := xml.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("failed to parse discovery XML: %v", err)
	}

	if discovery.NetZone.Name != "external-https" {
		t.Errorf("expected net-zone name 'external-https', got %q", discovery.NetZone.Name)
	}

	appNames := make(map[string]bool)
	for _, app := range discovery.NetZone.Apps {
		appNames[app.Name] = true
	}

	for _, expected := range []string{"Word", "Excel", "PowerPoint", "Draw", "Viewer"} {
		if !appNames[expected] {
			t.Errorf("expected app %q in discovery, not found", expected)
		}
	}
}

func TestDiscovery_URLSrcContainsClientURL(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://collabora.example.com",
		WOPIClientEditorPath: "/browser/dist/cool.html",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	var discovery WOPIDiscovery
	if err := xml.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("failed to parse discovery XML: %v", err)
	}

	expectedPrefix := "https://collabora.example.com/browser/dist/cool.html?WOPISrc="
	for _, app := range discovery.NetZone.Apps {
		for _, action := range app.Actions {
			if action.URLSrc != expectedPrefix {
				t.Errorf("app %q ext %q action %q: urlsrc = %q, want %q",
					app.Name, action.Ext, action.Name, action.URLSrc, expectedPrefix)
			}
		}
	}
}

func TestDiscovery_DocxHasEditAndView(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://example.com",
		WOPIClientEditorPath: "/editor",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	var discovery WOPIDiscovery
	if err := xml.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("failed to parse discovery XML: %v", err)
	}

	var foundEdit, foundView bool
	for _, app := range discovery.NetZone.Apps {
		for _, action := range app.Actions {
			if action.Ext == "docx" && action.Name == "edit" {
				foundEdit = true
			}
			if action.Ext == "docx" && action.Name == "view" {
				foundView = true
			}
		}
	}

	if !foundEdit {
		t.Error("expected edit action for docx")
	}
	if !foundView {
		t.Error("expected view action for docx")
	}
}

func TestDiscovery_PDFIsViewOnly(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://example.com",
		WOPIClientEditorPath: "/editor",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	var discovery WOPIDiscovery
	if err := xml.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("failed to parse discovery XML: %v", err)
	}

	var foundView, foundEdit bool
	for _, app := range discovery.NetZone.Apps {
		for _, action := range app.Actions {
			if action.Ext == "pdf" && action.Name == "view" {
				foundView = true
			}
			if action.Ext == "pdf" && action.Name == "edit" {
				foundEdit = true
			}
		}
	}

	if !foundView {
		t.Error("expected view action for pdf")
	}
	if foundEdit {
		t.Error("expected no edit action for pdf")
	}
}

func TestDiscovery_XMLDeclaration(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "https://example.com",
		WOPIClientEditorPath: "/editor",
	}

	req := httptest.NewRequest(http.MethodGet, "/hosting/discovery", nil)
	rr := httptest.NewRecorder()
	h.Discovery(rr, req)

	body := rr.Body.String()
	if !strings.HasPrefix(body, "<?xml") {
		t.Errorf("expected XML declaration at start, got: %s", body[:50])
	}
}

func TestBuildDiscoveryXML_CustomEditorPath(t *testing.T) {
	h := &Handler{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WOPIClientURL:        "http://localhost:9980",
		WOPIClientEditorPath: "/loleaflet/dist/loleaflet.html",
	}

	discovery := h.buildDiscoveryXML()

	expectedPrefix := "http://localhost:9980/loleaflet/dist/loleaflet.html?WOPISrc="
	for _, app := range discovery.NetZone.Apps {
		for _, action := range app.Actions {
			if action.URLSrc != expectedPrefix {
				t.Errorf("urlsrc = %q, want %q", action.URLSrc, expectedPrefix)
				return
			}
		}
	}
}
