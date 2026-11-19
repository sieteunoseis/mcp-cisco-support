# Multi-stage build. The builder and deps stages run on the build host's
# platform ($BUILDPLATFORM): the output (compiled JS, pure-JS node_modules with
# no native add-ons) is the same on every architecture, so the arm64 image
# needs no npm/node run under QEMU emulation (which crashed with SIGILL).
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder

# Build arguments
ARG BUILDTIME
ARG VERSION
ARG REVISION

# Create app directory
WORKDIR /usr/src/app

# Copy package files and tsconfig
COPY package*.json tsconfig.json tsconfig.build.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Production dependencies only (pure JS, no install scripts)
FROM --platform=$BUILDPLATFORM node:22-alpine AS deps
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Production stage
FROM node:22-alpine AS production

# Build arguments
ARG BUILDTIME
ARG VERSION
ARG REVISION

# Add build info as labels
LABEL org.opencontainers.image.created=${BUILDTIME}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${REVISION}
LABEL org.opencontainers.image.title="Cisco Support MCP Server"
LABEL org.opencontainers.image.description="MCP server for the Cisco Support APIs: bugs, security advisories, end-of-life, coverage, software, cases and RMAs"
LABEL org.opencontainers.image.vendor="sieteunoseis"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001

# Create app directory
WORKDIR /usr/src/app

# Copy package files and production dependencies (built natively in deps)
COPY package*.json ./
COPY --from=deps /usr/src/app/node_modules ./node_modules

# Copy built application from builder stage
COPY --from=builder /usr/src/app/dist ./dist

# Copy .env.example for reference
COPY --chown=nodeuser:nodejs .env.example ./


# Create logs directory
RUN mkdir -p logs && chown -R nodeuser:nodejs logs

# Expose port
# Containers must listen on all interfaces; publish the port deliberately
ENV HOST=0.0.0.0
EXPOSE 3000

# Switch to non-root user
USER nodeuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => { \
    process.exit(res.statusCode === 200 ? 0 : 1); \
  }).on('error', () => process.exit(1));"

# Start the application
ENTRYPOINT ["node", "dist/index.js"]
CMD ["--http"]