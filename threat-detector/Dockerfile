# Multi-stage build for security
FROM golang:1.21-alpine AS builder

# Security: Run as non-root user
RUN adduser -D -s /bin/sh appuser

WORKDIR /app

# Copy go mod files
COPY go.mod ./
COPY go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o threat-detector .

# Distroless final image for minimal attack surface
FROM gcr.io/distroless/static:nonroot

# Copy binary and set non-root user
COPY --from=builder /app/threat-detector /threat-detector
USER nonroot:nonroot

EXPOSE 8080
ENTRYPOINT ["/threat-detector"]