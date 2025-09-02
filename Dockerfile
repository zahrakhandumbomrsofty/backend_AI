# syntax=docker/dockerfile:1

FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    INSTANCE_PATH=/app/instance

WORKDIR /app

# Install Python dependencies first for better caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Ensure .env is included for python-dotenv
COPY .env /app/.env

# Copy application code
COPY . /app

# Prepare instance path for SQLite and runtime files
RUN mkdir -p "$INSTANCE_PATH"

# Run as non-root
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Start with gunicorn (module:object is task:app)
CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "4", "-b", "0.0.0.0:8080", "task:app"]
