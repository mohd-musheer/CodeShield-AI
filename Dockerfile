# Multi-stage build for CodeShield AI Production Dockerfile
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies needed for compiling python builds if any
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install python dependencies to a prefix directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Production Stage
FROM python:3.11-slim AS production

# Install Git (required by GitPython cloner) and curl (for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy python dependencies from builder to globally accessible location
COPY --from=builder /install /usr/local


# Create non-root group and user
RUN groupadd -g 10001 codeshield && \
    useradd -r -u 10001 -g codeshield -m codeshield

# Create volume mount directories and set ownership
RUN mkdir -p /app/reports /app/runtime/logs && \
    chown -R codeshield:codeshield /app

# Copy application directories
COPY --chown=codeshield:codeshield app/ /app/app/
COPY --chown=codeshield:codeshield static/ /app/static/

# Environment Variables
ENV HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set permissions
RUN chmod -R 755 /app/static

# Switch to non-root user
USER codeshield

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production startup command
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
