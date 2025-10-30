# Docker Setup Guide - ISP Billing System

## Overview
This guide covers setting up the ISP Billing application with PostgreSQL using Docker Compose.

## Ports Configuration
- **PostgreSQL**: `5434:5432` (External:Internal)
- **Web Application**: `8000:8000`

Note: Using port 5434 for PostgreSQL to avoid conflicts with other applications on the same server.

## Prerequisites
- Docker and Docker Compose installed
- Copy `.env.example` to `.env` and configure your environment variables

## Quick Start

### 1. Configure Environment Variables
```bash
cp .env.example .env
# Edit .env with your actual credentials
```

### 2. Build and Start Containers
```bash
docker-compose up -d --build
```

### 3. Initialize Database
```bash
# Wait for PostgreSQL to be ready (about 10 seconds)
docker-compose exec web python init_db.py
```

### 4. Verify Services
```bash
# Check container status
docker-compose ps

# Check logs
docker-compose logs -f web
docker-compose logs -f db

# Test API
curl http://localhost:8000/health
```

## Database Management

### Access PostgreSQL Container
```bash
docker-compose exec db psql -U isp_user -d isp_billing_db
```

### Backup Database
```bash
docker-compose exec db pg_dump -U isp_user isp_billing_db > backup_$(date +%Y%m%d).sql
```

### Restore Database
```bash
cat backup_20250101.sql | docker-compose exec -T db psql -U isp_user -d isp_billing_db
```

## Development Workflow

### View Logs
```bash
docker-compose logs -f web
```

### Restart Services
```bash
docker-compose restart web
```

### Stop Services
```bash
docker-compose down
```

### Stop and Remove Volumes (CAUTION: Deletes database)
```bash
docker-compose down -v
```

## Production Deployment

### 1. Update Environment Variables
Edit `.env` and set production values:
- Strong `SECRET_KEY`
- Production database credentials
- M-Pesa production credentials
- Actual MikroTik credentials

### 2. Use Production Build
```bash
docker-compose -f docker-compose.yml up -d --build
```

### 3. Enable SSL/TLS
Consider using a reverse proxy (nginx/traefik) with Let's Encrypt for HTTPS.

## Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose logs web
docker-compose logs db

# Restart containers
docker-compose restart
```

### Database Connection Issues
```bash
# Verify PostgreSQL is running
docker-compose exec db pg_isready -U isp_user

# Check connection from web container
docker-compose exec web python -c "from app.db.database import async_engine; print('Connection OK')"
```

### Reset Everything
```bash
docker-compose down -v
docker-compose up -d --build
docker-compose exec web python init_db.py
```

## API Endpoints
- Health Check: http://localhost:8000/health
- API Docs: http://localhost:8000/docs
- Root: http://localhost:8000/

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| DATABASE_URL | PostgreSQL connection string | postgresql+asyncpg://user:pass@db:5432/dbname |
| SECRET_KEY | JWT secret key | your-secret-key |
| MIKROTIK_HOST | MikroTik router IP | 10.0.0.2 |
| MIKROTIK_USERNAME | MikroTik username | admin |
| MIKROTIK_PASSWORD | MikroTik password | your-password |
| MPESA_* | M-Pesa API credentials | See M-Pesa docs |

