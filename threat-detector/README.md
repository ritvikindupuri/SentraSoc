# Threat Detector Service

A Go-based threat detection service for Kubernetes security monitoring.

## Building

### Prerequisites
- Go 1.21 or later
- Docker

### Local Development

```bash
# Initialize Go modules (first time only)
go mod tidy

# Run locally
go run main.go

# Build binary
go build -o threat-detector .
```

### Docker Build

```bash
# Build Docker image
docker build -t threat-detector:latest .

# For local Kubernetes testing with minikube
eval $(minikube docker-env)
docker build -t threat-detector:latest .

# For kind
docker build -t threat-detector:latest .
kind load docker-image threat-detector:latest
```

## Configuration

The service runs on port 8080 by default. Set the `PORT` environment variable to change this.

## API Endpoints

- `GET /events` - Get threat events
- `GET /health` - Health check

## Kubernetes Deployment

The service requires appropriate RBAC permissions to monitor cluster resources. See the RBAC configuration in `k8s/rbac/service-accounts.yaml`.