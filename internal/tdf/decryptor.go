package tdf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/sdk"
)

const maxDecryptSize = 256 << 20 // 256 MB

// Config holds the settings needed to initialise a TDF Decryptor.
type Config struct {
	PlatformEndpoint       string
	ClientID, ClientSecret string
	FulfillableObligations []string
	InsecureSkipVerify     bool // skip TLS verification (development only)
	Logger                 *slog.Logger
}

// Decryptor wraps the OpenTDF SDK to decrypt TDF-wrapped files.
type Decryptor struct {
	sdk         *sdk.SDK
	fulfillable []string
	logger      *slog.Logger
}

// NewDecryptor creates a Decryptor that connects to the given OpenTDF platform.
func NewDecryptor(cfg Config) (*Decryptor, error) {
	opts := []sdk.Option{
		sdk.WithClientCredentials(cfg.ClientID, cfg.ClientSecret, nil),
	}
	if cfg.InsecureSkipVerify {
		opts = append(opts, sdk.WithInsecureSkipVerifyConn())
	}
	s, err := sdk.New(cfg.PlatformEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("tdf: creating SDK: %w", err)
	}
	return &Decryptor{
		sdk:         s,
		fulfillable: cfg.FulfillableObligations,
		logger:      cfg.Logger,
	}, nil
}

// IsTDFContentType returns true when the content-type indicates a TDF-wrapped
// payload (e.g. "tdf;application/vnd.openxmlformats-...").
func IsTDFContentType(ct string) bool {
	return strings.HasPrefix(ct, "tdf;")
}

// Decrypt reads a TDF stream, unwraps it via the platform KAS, and returns
// the decrypted plaintext bytes.
func (d *Decryptor) Decrypt(ctx context.Context, r io.Reader) ([]byte, error) {
	// LoadTDF requires io.ReadSeeker, so buffer the stream.
	limited := io.LimitReader(r, maxDecryptSize+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("tdf: buffering TDF stream: %w", err)
	}
	if len(buf) > maxDecryptSize {
		return nil, fmt.Errorf("tdf: file exceeds %d byte limit", maxDecryptSize)
	}

	reader, err := d.sdk.LoadTDF(bytes.NewReader(buf),
		sdk.WithTDFFulfillableObligationFQNs(d.fulfillable),
	)
	if err != nil {
		return nil, fmt.Errorf("tdf: loading TDF: %w", err)
	}

	if err := reader.Init(ctx); err != nil {
		return nil, fmt.Errorf("tdf: unwrapping key: %w", err)
	}

	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("tdf: reading decrypted payload: %w", err)
	}

	d.logger.Info("TDF detected, decrypting via SDK", "encrypted_size", len(buf), "decrypted_size", len(plaintext))
	return plaintext, nil
}
