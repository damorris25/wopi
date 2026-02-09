# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /wopi-server ./cmd/wopi-server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

RUN addgroup -S wopi && adduser -S wopi -G wopi

COPY --from=builder /wopi-server /usr/local/bin/wopi-server

USER wopi

EXPOSE 8080

ENTRYPOINT ["wopi-server"]
