# WOPI Server

A Go implementation of the [Web Application Open Platform Interface (WOPI)](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/concepts) protocol that uses S3-compatible storage as its backend. This service enables web-based office applications (such as Microsoft Office Online or Collabora Online) to open, edit, and collaborate on documents stored in any S3-compatible object store.

## What It Does

This server acts as a **WOPI host** — the bridge between a WOPI client (the browser-based office editor) and your document storage. When a user opens a document for editing in their browser, the WOPI client communicates with this server to:

- Retrieve file metadata (name, size, version, permissions)
- Download file contents for editing
- Save changes back to storage
- Manage collaborative editing locks so multiple users don't overwrite each other's changes
- Rename and delete files

All documents are stored in an S3-compatible bucket (AWS S3, MinIO, Ceph, DigitalOcean Spaces, etc.), which you configure via environment variables.

## How It Works

### Architecture

```
┌──────────────┐     WOPI Protocol     ┌──────────────┐     S3 API     ┌──────────────┐
│  Web Browser  │ ◄──────────────────► │  WOPI Server  │ ◄────────────► │  S3 Storage   │
│  (Office App) │   HTTP + JSON/Binary  │  (this repo)  │   GetObject    │  (any S3-     │
│               │                       │               │   PutObject    │   compatible)  │
└──────────────┘                       └──────────────┘   HeadObject    └──────────────┘
                                                          DeleteObject
                                                          CopyObject
```

### WOPI Protocol Flow

1. Your application generates a **WOPI action URL** that points the browser-based editor to this server
2. The editor calls **CheckFileInfo** (`GET /wopi/files/{file_id}`) to learn about the file's properties and the user's permissions
3. The editor calls **GetFile** (`GET /wopi/files/{file_id}/contents`) to download the document
4. Before saving, the editor acquires a **Lock** (`POST /wopi/files/{file_id}` with `X-WOPI-Override: LOCK`) — locks auto-expire after 30 minutes per the WOPI spec
5. The editor saves changes via **PutFile** (`POST /wopi/files/{file_id}/contents` with `X-WOPI-Override: PUT`)
6. When done, the editor calls **Unlock** to release the file

### Implemented WOPI Operations

| Operation | Method | Endpoint | Description |
|-----------|--------|----------|-------------|
| Discovery | `GET` | `/hosting/discovery` | Returns WOPI discovery XML (supported file types and actions) |
| CheckFileInfo | `GET` | `/wopi/files/{file_id}` | Returns file metadata and user permissions |
| GetFile | `GET` | `/wopi/files/{file_id}/contents` | Returns the binary file contents |
| PutFile | `POST` | `/wopi/files/{file_id}/contents` | Writes new file contents (requires lock) |
| Lock | `POST` | `/wopi/files/{file_id}` | Acquires or refreshes a 30-minute lock |
| GetLock | `POST` | `/wopi/files/{file_id}` | Returns the current lock ID |
| RefreshLock | `POST` | `/wopi/files/{file_id}` | Extends the lock expiration timer |
| Unlock | `POST` | `/wopi/files/{file_id}` | Releases a lock |
| UnlockAndRelock | `POST` | `/wopi/files/{file_id}` | Atomically replaces a lock |
| DeleteFile | `POST` | `/wopi/files/{file_id}` | Deletes a file |
| RenameFile | `POST` | `/wopi/files/{file_id}` | Renames a file |
| PutRelativeFile | `POST` | `/wopi/files/{file_id}` | Creates a new file relative to an existing one |

POST operations to `/wopi/files/{file_id}` are dispatched using the `X-WOPI-Override` header.

### Authentication

Access tokens are HMAC-SHA256 signed tokens scoped to a specific user and file. The server includes a `/token` endpoint for generating tokens during development. In production, your application should generate tokens and pass them as the `access_token` query parameter on WOPI URLs.

Tokens can be passed via:
- Query parameter: `?access_token={token}`
- Header: `Authorization: Bearer {token}`

Tokens expire after 10 hours, as recommended by the WOPI specification.

### File ID Format

S3 object keys use `/` as a path separator, but WOPI file IDs must be URL-safe. This server uses `|` as the separator in file IDs, which maps directly to `/` in S3 keys:

- File ID: `documents|quarterly-report.docx`
- S3 Key: `documents/quarterly-report.docx`

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPI_PORT` | `8080` | HTTP server port |
| `WOPI_BASE_URL` | `http://localhost:8080` | External URL for constructing WOPISrc values |
| `WOPI_ACCESS_TOKEN_SECRET` | `change-me-in-production` | Secret for signing access tokens |
| `S3_ENDPOINT` | `http://localhost:9000` | S3-compatible storage endpoint URL |
| `S3_REGION` | `us-east-1` | S3 region |
| `S3_BUCKET` | `wopi-documents` | S3 bucket name |
| `S3_ACCESS_KEY_ID` | `minioadmin` | S3 access key |
| `S3_SECRET_ACCESS_KEY` | `minioadmin` | S3 secret key |
| `S3_USE_SSL` | `true` | Use HTTPS for S3 connections |
| `S3_FORCE_PATH_STYLE` | `true` | Use path-style S3 URLs (required for MinIO and most S3-compatible stores) |

## Running

### With Docker Compose (recommended for development)

Docker Compose starts the WOPI server alongside a MinIO instance that provides S3-compatible storage locally:

```bash
docker compose up --build
```

This starts:
- **WOPI server** on port `8080`
- **MinIO** on port `9000` (API) and `9001` (web console)
- An init container that creates the `wopi-documents` bucket

You can then upload a test file via the MinIO console at `http://localhost:9001` (login: `minioadmin`/`minioadmin`).

### With Docker (standalone)

```bash
# Build the image
docker build -t wopi-server .

# Run with your S3-compatible storage
docker run -p 8080:8080 \
  -e S3_ENDPOINT=https://your-s3-endpoint.com \
  -e S3_BUCKET=your-bucket \
  -e S3_ACCESS_KEY_ID=your-key \
  -e S3_SECRET_ACCESS_KEY=your-secret \
  -e S3_USE_SSL=true \
  -e WOPI_ACCESS_TOKEN_SECRET=your-secret-key \
  -e WOPI_BASE_URL=https://your-wopi-host.com \
  wopi-server
```

### Running Locally (without Docker)

```bash
# Install Go 1.23+
# Set environment variables (see .env.example)
cp .env.example .env
source .env

go run ./cmd/wopi-server
```

### Verifying the Server

```bash
# Health check
curl http://localhost:8080/health

# Generate a token (development only)
curl -X POST "http://localhost:8080/token?user_id=testuser&file_id=test.docx"

# Check file info (replace TOKEN with the access_token from above)
curl "http://localhost:8080/wopi/files/test.docx?access_token=TOKEN"

# Download file contents
curl "http://localhost:8080/wopi/files/test.docx/contents?access_token=TOKEN"
```

## Running Tests

```bash
go test ./... -v
```

To run tests with coverage:

```bash
go test ./... -v -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

## Project Structure

```
.
├── cmd/
│   └── wopi-server/
│       └── main.go              # Entry point, HTTP server setup, routing
├── internal/
│   ├── config/
│   │   └── config.go            # Environment-based configuration
│   ├── handlers/
│   │   ├── handlers.go          # WOPI HTTP request handlers
│   │   └── handlers_test.go     # Handler tests with mock S3
│   ├── middleware/
│   │   ├── auth.go              # Token validation, request logging
│   │   └── auth_test.go         # Middleware tests
│   ├── storage/
│   │   ├── s3.go                # S3-compatible storage operations
│   │   └── s3_test.go           # Storage tests with mock S3
│   └── wopi/
│       ├── types.go             # WOPI response types and constants
│       ├── lock.go              # In-memory lock manager
│       └── lock_test.go         # Lock manager tests
├── Dockerfile                   # Multi-stage build
├── docker-compose.yml           # Local dev with MinIO
├── .env.example                 # Configuration template
├── go.mod
└── go.sum
```

## Integrating with a WOPI Client

To use this server with an actual office editor, you need a WOPI client such as:

- **Collabora Online** — open-source, based on LibreOffice
- **Microsoft Office Online** — requires enrollment in the Cloud Storage Partner Program
- **ONLYOFFICE** — open-source document editor

The general integration pattern:

1. Deploy this WOPI server so it's accessible from both the WOPI client and user browsers
2. For each document a user wants to edit, construct a WOPI action URL:
   ```
   https://{wopi-client-host}/loleaflet/dist/loleaflet.html?WOPISrc=https://{wopi-server-host}/wopi/files/{file_id}&access_token={token}
   ```
3. Embed this URL in an iframe in your web application
4. The WOPI client handles the editing UI and communicates with this server via the WOPI protocol

## Limitations

- **Lock storage is in-memory.** Locks are lost on server restart. For production use with multiple server instances, replace the lock manager with a distributed store (Redis, DynamoDB, etc.).
- **No proof key validation.** The server uses HMAC-based access tokens but does not validate WOPI proof keys from the client. This is acceptable for deployments behind a private network but should be added for public-facing deployments.

## License

MIT
