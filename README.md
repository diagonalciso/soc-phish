# Project

Standalone threat intelligence and security monitoring service.

## Quick Start

```bash
cp .env.example .env
nano .env
python3 app.py
```

## Configuration

See `.env.example` for all variables.

## Architecture

- HTTP REST API
- SQLite local database
- Integration with SOCint and SOCops platforms

## Integration

All services feed findings to SOCint intelligence platform and can push alerts to SOCops.
