package handlers

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

// WOPI Discovery XML types per the WOPI specification.
// See: https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/online/discovery

// WOPIDiscovery is the root element of the WOPI discovery XML.
type WOPIDiscovery struct {
	XMLName xml.Name       `xml:"wopi-discovery"`
	NetZone WOPINetZone    `xml:"net-zone"`
	ProofKey *WOPIProofKey `xml:"proof-key,omitempty"`
}

// WOPINetZone groups apps by network zone.
type WOPINetZone struct {
	Name string    `xml:"name,attr"`
	Apps []WOPIApp `xml:"app"`
}

// WOPIApp describes a WOPI application (e.g., Word, Excel) and its supported actions.
type WOPIApp struct {
	Name      string       `xml:"name,attr"`
	FavIconURL string      `xml:"favIconUrl,attr,omitempty"`
	Actions   []WOPIAction `xml:"action"`
}

// WOPIAction describes a single action (view, edit) for a file extension.
type WOPIAction struct {
	Name    string `xml:"name,attr"`
	Ext     string `xml:"ext,attr,omitempty"`
	URLSrc  string `xml:"urlsrc,attr"`
	Default bool   `xml:"default,attr,omitempty"`
}

// WOPIProofKey holds public keys for proof validation (optional).
type WOPIProofKey struct {
	OldValue  string `xml:"oldvalue,attr,omitempty"`
	OldModulus string `xml:"oldmodulus,attr,omitempty"`
	OldExponent string `xml:"oldexponent,attr,omitempty"`
	Value     string `xml:"value,attr,omitempty"`
	Modulus   string `xml:"modulus,attr,omitempty"`
	Exponent  string `xml:"exponent,attr,omitempty"`
}

// discoveryApp defines a WOPI application with its supported extensions.
type discoveryApp struct {
	name       string
	extensions []string
}

// supportedApps lists the WOPI applications and file extensions that this
// server supports for editing. These correspond to the document types
// Collabora Online / LibreOffice Online can handle.
var supportedApps = []discoveryApp{
	{
		name: "Word",
		extensions: []string{
			"doc", "docm", "docx", "dot", "dotm", "dotx", "odt", "ott", "rtf", "txt",
		},
	},
	{
		name: "Excel",
		extensions: []string{
			"csv", "ods", "ots", "xls", "xlsb", "xlsm", "xlsx", "xlt", "xltm", "xltx",
		},
	},
	{
		name: "PowerPoint",
		extensions: []string{
			"odp", "otp", "pot", "potm", "potx", "pps", "ppsm", "ppsx", "ppt", "pptm", "pptx",
		},
	},
	{
		name: "Draw",
		extensions: []string{
			"odg", "otg", "vsd", "vsdx",
		},
	},
}

// viewOnlyExtensions lists formats that can be viewed but not edited.
var viewOnlyExtensions = []string{
	"pdf", "epub",
}

// buildDiscoveryXML generates the WOPI discovery XML document.
func (h *Handler) buildDiscoveryXML() WOPIDiscovery {
	baseURLSrc := fmt.Sprintf("%s%s?WOPISrc=",
		h.WOPIClientURL,
		h.WOPIClientEditorPath,
	)

	var apps []WOPIApp
	for _, da := range supportedApps {
		app := WOPIApp{Name: da.name}
		for _, ext := range da.extensions {
			app.Actions = append(app.Actions,
				WOPIAction{Name: "edit", Ext: ext, URLSrc: baseURLSrc, Default: true},
				WOPIAction{Name: "view", Ext: ext, URLSrc: baseURLSrc},
			)
		}
		apps = append(apps, app)
	}

	// Add view-only formats.
	viewApp := WOPIApp{Name: "Viewer"}
	for _, ext := range viewOnlyExtensions {
		viewApp.Actions = append(viewApp.Actions,
			WOPIAction{Name: "view", Ext: ext, URLSrc: baseURLSrc, Default: true},
		)
	}
	apps = append(apps, viewApp)

	return WOPIDiscovery{
		NetZone: WOPINetZone{
			Name: "external-https",
			Apps: apps,
		},
	}
}

// Discovery handles GET /hosting/discovery — returns WOPI discovery XML
// describing the file types and actions this server supports.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	discovery := h.buildDiscoveryXML()

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(discovery); err != nil {
		h.Logger.Error("failed to encode discovery XML", "error", err)
	}
}
