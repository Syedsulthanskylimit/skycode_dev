# ---------- Stage 1: Builder ----------
FROM python:3.10-alpine AS builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    gcc musl-dev libffi-dev openssl-dev python3-dev \
    cargo jpeg-dev zlib-dev

# Copy requirements
COPY requirements.txt .

# Build Python wheels (cached dependencies for smaller runtime image)
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ---------- Stage 2: Runtime ----------
FROM python:3.10-alpine
WORKDIR /app

# Environment settings for Django
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install runtime dependencies (no Redis server here!)
RUN apk add --no-cache bash

# Copy Python deps from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy project files
COPY . .

# Expose Django port
EXPOSE 8000

# Default command: run migrations + start Django server
CMD sh -c "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"

