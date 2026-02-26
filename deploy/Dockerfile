# ==============================================================================
# Java Text Intelligence - Production Dockerfile
#
# Multi-stage build:
#   1. Build custom Caddy with rate limiting module
#   2. Build frontend
#   3. Build Java shaded JAR
#   4. Run with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build custom Caddy with rate limiting module
FROM golang:1.23-alpine AS caddy-build

WORKDIR /build
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/mholt/caddy-ratelimit

# Stage 2: Build frontend
FROM node:24-alpine AS frontend-build

RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /build/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./dist/index.html

# Stage 3: Build Java application
FROM maven:3.9-eclipse-temurin-21-alpine AS java-build

WORKDIR /build
COPY pom.xml ./
RUN mvn dependency:resolve
COPY src/ ./src/
COPY deepgram.toml ./
RUN mvn package -DskipTests

# Stage 4: Production image with Caddy
FROM eclipse-temurin:21-jre-alpine

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy custom Caddy with rate limiting
COPY --from=caddy-build /build/caddy /usr/bin/caddy

WORKDIR /app

# Copy Java shaded JAR
COPY --from=java-build /build/target/java-text-intelligence-1.0.0-shaded.jar ./java-text-intelligence-1.0.0-shaded.jar
COPY --from=java-build /build/deepgram.toml ./deepgram.toml

# Copy built frontend
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Copy Caddy configuration and start script
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

# Set environment variables
ENV BACKEND_PORT=8081
ENV PORT=8081
ENV HOST=0.0.0.0
ENV BACKEND_CMD="java -jar /app/java-text-intelligence-1.0.0-shaded.jar"

EXPOSE 8080

CMD ["./start.sh"]
