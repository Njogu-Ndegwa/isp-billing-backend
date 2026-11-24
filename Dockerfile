FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

# Copy application code
COPY . .

# The commit this image was built from (deploy.yml passes it). Read by
# ops_health.app_version() for heartbeats and the deploy markers on the admin
# router CPU chart. Last, so a new commit never invalidates the pip layer.
ARG GIT_SHA=unknown
ENV GIT_SHA=$GIT_SHA

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

