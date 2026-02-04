# syntax=docker/dockerfile:1.4
# ============================================================================
# AIS Forge - Modern Multi-Environment Dockerfile
# ============================================================================
# Supports: development, preview, and production environments
# Optimized for security, performance, and CI/CD integration
#
# Build examples:
#   Development:  docker build --target development -t ais-forge:dev .
#   Preview:      docker build --target preview -t ais-forge:preview .
#   Production:   docker build --target production -t ais-forge:prod .
#
# With BuildKit cache:
#   docker build --target production \
#     --cache-from type=registry,ref=ghcr.io/org/ais-forge:cache \
#     --cache-to type=registry,ref=ghcr.io/org/ais-forge:cache,mode=max \
#     -t ais-forge:prod .

# ============================================================================
# Build Arguments
# ============================================================================
ARG NODE_VERSION=20
ARG PNPM_VERSION=10.28.2
ARG ALPINE_VERSION=3.19

# ============================================================================
# Stage: base
# Common base stage for all environments
# ============================================================================
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS base

# Install security updates and dumb-init
RUN --mount=type=cache,target=/var/cache/apk \
    apk upgrade --no-cache && \
    apk add --no-cache \
        dumb-init \
        tini \
        tzdata

# Enable corepack and configure pnpm
ARG PNPM_VERSION
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV COREPACK_INTEGRITY_KEYS=0
RUN corepack enable && \
    corepack prepare pnpm@${PNPM_VERSION} --activate

# Configure pnpm store
ENV PNPM_STORE_PATH="/root/.local/share/pnpm/store"

WORKDIR /app

# ============================================================================
# Stage: dependencies
# Install all dependencies (dev + prod)
# ============================================================================
FROM base AS dependencies

# Copy package manager files only for better cache invalidation
COPY --link package.json pnpm-lock.yaml ./

# Install all dependencies with cache mount for faster rebuilds
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

# ============================================================================
# Stage: dependencies-prod
# Install production dependencies only
# ============================================================================
FROM base AS dependencies-prod

COPY --link package.json pnpm-lock.yaml ./

# Install production dependencies with cache mount
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --prod

# ============================================================================
# Stage: builder
# Build the application
# ============================================================================
FROM base AS builder

# Copy dependencies from dependencies stage
COPY --from=dependencies --link /app/node_modules ./node_modules

# Copy source code
COPY --link . .

# Build the application
RUN pnpm run build

# Generate database migrations (optional, can fail gracefully)
RUN pnpm run db:generate 2>/dev/null || \
    echo "⚠️  No new database migrations to generate"

# Run type checking
RUN pnpm run typecheck

# Run linting (optional, comment out if too strict for CI)
# RUN pnpm run lint

# ============================================================================
# Stage: development
# Development environment with hot-reload
# ============================================================================
FROM base AS development

# Install development tools
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        git \
        openssh-client \
        curl

# Copy all dependencies (including dev dependencies)
COPY --from=dependencies --link /app/node_modules ./node_modules

# Copy source code
COPY --link . .

# Set development environment
ENV NODE_ENV=development
ENV LOG_LEVEL=debug

# Create non-root user
RUN addgroup -g 1001 -S aisforge && \
    adduser -S aisforge -u 1001 -G aisforge && \
    chown -R aisforge:aisforge /app

USER aisforge

EXPOSE 3000 9090

# Use tini for proper signal handling in dev
ENTRYPOINT ["tini", "--"]

# Start with hot-reload
CMD ["pnpm", "run", "dev"]

# ============================================================================
# Stage: preview
# Preview/staging environment (closer to production)
# ============================================================================
FROM base AS preview

# Copy production dependencies
COPY --from=dependencies-prod --link /app/node_modules ./node_modules

# Copy built application
COPY --from=builder --link /app/dist ./dist

# Copy database migrations
COPY --from=builder --link /app/drizzle ./drizzle

# Copy configuration files
COPY --link config.example.yaml ./

# Copy package.json for metadata
COPY --link package.json ./

# Set preview environment
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV IS_PREVIEW=true

# Security hardening
RUN addgroup -g 1001 -S aisforge && \
    adduser -S aisforge -u 1001 -G aisforge && \
    chown -R aisforge:aisforge /app && \
    chmod -R 550 /app && \
    chmod -R 750 /app/drizzle

USER aisforge

EXPOSE 3000 9090

# Health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD node -e "const http=require('http');http.get('http://localhost:3000/health',(r)=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]

CMD ["node", "dist/index.js"]

# ============================================================================
# Stage: production
# Production environment (minimal, secure, optimized)
# ============================================================================
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS production

# Install only essential runtime dependencies
RUN --mount=type=cache,target=/var/cache/apk \
    apk upgrade --no-cache && \
    apk add --no-cache \
        dumb-init \
        tzdata \
        ca-certificates && \
    rm -rf /var/cache/apk/* /tmp/*

WORKDIR /app

# Copy production dependencies
COPY --from=dependencies-prod --link --chown=1001:1001 /app/node_modules ./node_modules

# Copy built application
COPY --from=builder --link --chown=1001:1001 /app/dist ./dist

# Copy database migrations
COPY --from=builder --link --chown=1001:1001 /app/drizzle ./drizzle

# Copy configuration files
COPY --link --chown=1001:1001 config.example.yaml ./

# Copy package.json for metadata
COPY --link --chown=1001:1001 package.json ./

# Set production environment variables
ENV NODE_ENV=production \
    LOG_LEVEL=info \
    NODE_OPTIONS="--max-old-space-size=2048 --enable-source-maps" \
    # Security headers
    NODE_NO_WARNINGS=1

# Create non-root user with minimal permissions
RUN addgroup -g 1001 -S aisforge && \
    adduser -S aisforge -u 1001 -G aisforge && \
    # Set secure permissions (read-only except for necessary directories)
    chmod -R 550 /app && \
    chmod -R 750 /app/drizzle && \
    # Remove write permissions from all files
    find /app -type f -exec chmod 440 {} \; && \
    # Ensure executables are executable
    find /app/dist -type f -name "*.js" -exec chmod 550 {} \;

# Switch to non-root user
USER aisforge

# Expose application and metrics ports
EXPOSE 3000 9090

# Add labels for metadata and traceability
LABEL maintainer="SkyZon - Jean-Pierre Dupuis" \
      org.opencontainers.image.title="AIS Forge" \
      org.opencontainers.image.description="Modern authentication and identity service" \
      org.opencontainers.image.vendor="SkyZon" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/skyzon/ais-forge" \
      org.opencontainers.image.version="0.0.3-beta"

# Optimized health check for production
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD node -e "const http=require('http');http.get('http://localhost:3000/health',(r)=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

# Use dumb-init for proper signal handling (PID 1)
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/index.js"]
