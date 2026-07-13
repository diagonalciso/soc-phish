# Project

> Email parser + IOC extraction

<p align="center">
  <img src="docs/screenshot.png" alt="soc-phish dashboard screenshot" width="100%">
</p>


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


## Documentation

See **[MANUAL.md](MANUAL.md)** for the full manual (overview, configuration, endpoints, integration, troubleshooting). In the running dashboard, click the **`?` Help button** in the top-right corner to open it at `/manual`.
