# Docker Deployment Guide

Comprehensive guide for deploying the Cisco Support MCP Server using Docker containers.

## Quick Start

### Pre-built Image from GitHub Container Registry

```bash
# Pull the latest image
docker pull ghcr.io/sieteunoseis/mcp-cisco-support:latest

# Run with basic configuration
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e SUPPORT_API=bug,case,eox \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Docker Compose (Recommended)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  cisco-support:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    ports:
      - "3000:3000"
    environment:
      - CISCO_CLIENT_ID=your_client_id_here
      - CISCO_CLIENT_SECRET=your_client_secret_here
      - SUPPORT_API=bug,case,eox,psirt,product,software
      - MCP_BEARER_TOKEN=your_secure_token
      - NODE_ENV=production
    command: ["--http"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

Run with Docker Compose:
```bash
docker-compose up -d
```

## Available Images

### GitHub Container Registry

The project provides automated builds via GitHub Actions:

- **Latest**: `ghcr.io/sieteunoseis/mcp-cisco-support:latest`
- **Tagged Versions**: `ghcr.io/sieteunoseis/mcp-cisco-support:v1.0.0`
- **Branch Builds**: `ghcr.io/sieteunoseis/mcp-cisco-support:main-abc123`

### Multi-Platform Support

All images support multiple architectures:
- `linux/amd64` (Intel/AMD x64)
- `linux/arm64` (ARM64/Apple Silicon)

## Configuration Options

### Basic Configuration

```bash
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Advanced Configuration

```bash
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e SUPPORT_API=bug,case,eox,psirt,product,software \
  -e MCP_BEARER_TOKEN=your_secure_token \
  -e NODE_ENV=production \
  -e PORT=3000 \
  --name cisco-support \
  --restart unless-stopped \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Volume Mounts

```bash
# Mount configuration and logs
docker run -p 3000:3000 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/logs:/app/logs \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

## Security Configuration

### With Authentication (Recommended)

```bash
# Generate secure token first
docker run --rm ghcr.io/sieteunoseis/mcp-cisco-support:latest --generate-token

# Use the generated token
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e MCP_BEARER_TOKEN=generated_token_here \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Without Authentication (Development Only)

```bash
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e DANGEROUSLY_OMIT_AUTH=true \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Using Docker Secrets

For production deployments with Docker Swarm:

```yaml
version: '3.8'

services:
  cisco-support:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    ports:
      - "3000:3000"
    environment:
      - CISCO_CLIENT_ID_FILE=/run/secrets/cisco_client_id
      - CISCO_CLIENT_SECRET_FILE=/run/secrets/cisco_client_secret
      - MCP_BEARER_TOKEN_FILE=/run/secrets/mcp_bearer_token
    secrets:
      - cisco_client_id
      - cisco_client_secret
      - mcp_bearer_token
    command: ["--http"]

secrets:
  cisco_client_id:
    external: true
  cisco_client_secret:
    external: true
  mcp_bearer_token:
    external: true
```

## Production Deployment

### Full Production Configuration

```yaml
version: '3.8'

services:
  cisco-support:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    ports:
      - "3000:3000"
    environment:
      - CISCO_CLIENT_ID=your_client_id
      - CISCO_CLIENT_SECRET=your_client_secret
      - SUPPORT_API=bug,case,eox,psirt,product,software
      - MCP_BEARER_TOKEN=your_secure_token
      - NODE_ENV=production
      - LOG_LEVEL=info
    command: ["--http"]
    restart: unless-stopped
    
    # Health checks
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    
    # Logging configuration
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    
    # Security context
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    
    # Labels for monitoring
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=3000"
      - "prometheus.io/path=/health"

  # Optional: Reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - cisco-support
    restart: unless-stopped
```

### Load Balancing

For high availability deployments:

```yaml
version: '3.8'

services:
  cisco-support-1:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    environment:
      - CISCO_CLIENT_ID=your_client_id
      - CISCO_CLIENT_SECRET=your_client_secret
      - MCP_BEARER_TOKEN=your_secure_token
    command: ["--http"]
    
  cisco-support-2:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    environment:
      - CISCO_CLIENT_ID=your_client_id
      - CISCO_CLIENT_SECRET=your_client_secret
      - MCP_BEARER_TOKEN=your_secure_token
    command: ["--http"]
    
  nginx-lb:
    image: nginx:alpine
    ports:
      - "3000:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - cisco-support-1
      - cisco-support-2
```

## Building from Source

### Build Local Image

```bash
# Clone repository
git clone https://github.com/sieteunoseis/mcp-cisco-support.git
cd mcp-cisco-support

# Build image
docker build -t mcp-cisco-support:local .

# Run local build
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  mcp-cisco-support:local --http
```

### Multi-stage Build Process

The Dockerfile uses multi-stage builds for optimization:

```dockerfile
# Build stage
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY . .
RUN npm run build

# Production stage
FROM node:18-alpine AS runtime
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
WORKDIR /app
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json

USER nodejs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["node", "dist/index.js"]
```

## Monitoring and Logging

### Health Monitoring

```bash
# Check container health
docker inspect cisco-support-container --format='{{.State.Health.Status}}'

# View health check logs
docker inspect cisco-support-container --format='{{range .State.Health.Log}}{{.Output}}{{end}}'

# Monitor in real-time
watch -n 5 'docker inspect cisco-support-container --format="{{.State.Health.Status}}"'
```

### Log Management

```bash
# View container logs
docker logs cisco-support-container

# Follow logs in real-time
docker logs -f cisco-support-container

# View logs with timestamps
docker logs -t cisco-support-container

# Limit log output
docker logs --tail 100 cisco-support-container
```

### Log Configuration

```yaml
# docker-compose.yml logging section
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    
# Alternative: Syslog driver
logging:
  driver: "syslog"
  options:
    syslog-address: "tcp://log-server:514"
    tag: "cisco-support"
```

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check container status
docker ps -a

# View startup logs
docker logs container-name

# Inspect container configuration
docker inspect container-name
```

#### Environment Variables Not Working

```bash
# Test environment variables
docker exec container-name env | grep CISCO

# Debug with shell access
docker exec -it container-name sh
echo $CISCO_CLIENT_ID
```

#### Network Connectivity Issues

```bash
# Test network connectivity from container
docker exec container-name curl -I https://apix.cisco.com

# Check port binding
docker port container-name

# Test from host
curl http://localhost:3000/health
```

#### Permission Errors

```bash
# Check user context
docker exec container-name id

# Run with different user
docker run --user 1000:1000 ...

# Check file permissions
docker exec container-name ls -la /app
```

### Debugging Commands

```bash
# Interactive shell in container
docker exec -it container-name sh

# View container resource usage
docker stats container-name

# Inspect container configuration
docker inspect container-name | jq '.Config.Env'

# Check container processes
docker exec container-name ps aux

# Test API endpoints
docker exec container-name curl http://localhost:3000/health
```

## Performance Optimization

### Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

### Memory Management

```bash
# Monitor memory usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Set memory limits
docker run --memory=512m --memory-swap=1g ...
```

### Build Optimization

```dockerfile
# Use .dockerignore to exclude unnecessary files
# Multi-stage builds to reduce image size
# Cache npm dependencies separately from source code
# Use specific package versions for reproducible builds
```

## Security Best Practices

### Container Security

- Run as non-root user
- Use read-only filesystem where possible
- Limit resource usage
- Regular image updates
- Scan for vulnerabilities

### Secrets Management

```bash
# Don't put secrets in environment variables
# Use Docker secrets or external secret management
# Rotate credentials regularly
# Use least privilege access
```

### Network Security

```yaml
# Use custom networks
networks:
  cisco-support:
    driver: bridge
    
services:
  cisco-support:
    networks:
      - cisco-support
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Deploy to Production

on:
  push:
    tags: ['v*']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to server
        run: |
          docker pull ghcr.io/sieteunoseis/mcp-cisco-support:${{ github.ref_name }}
          docker-compose down
          docker-compose up -d
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cisco-support
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cisco-support
  template:
    metadata:
      labels:
        app: cisco-support
    spec:
      containers:
      - name: cisco-support
        image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
        ports:
        - containerPort: 3000
        env:
        - name: CISCO_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: cisco-credentials
              key: client-id
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
```