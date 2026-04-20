# Secure Bounty Board

![Status](https://img.shields.io/badge/status-active-0f766e)
![Stack](https://img.shields.io/badge/stack-React%20%7C%20Go%20%7C%20PostgreSQL-1d4ed8)
![License](https://img.shields.io/badge/license-MIT-2563eb)

Enterprise-style vulnerability management platform for modern bug bounty operations, combining secure workflows, AI-assisted triage context, and audit-ready tracking.

## Overview

Secure Bounty Board is built to manage vulnerability reports from intake to resolution in a structured, security-focused workflow.

### Core Capabilities

- Authentication and role-based access control
- Findings management and triage lifecycle
- AI-assisted context for prioritization
- Audit logs for operational traceability
- Dashboard-style visibility for analysts and admins

## Architecture

- Frontend: React + Vite
- Backend: Go REST API
- Database: PostgreSQL
- Local Infra: Docker Compose

## Repository Structure

- `frontend` - Web client and UI layer
- `backend` - API services and domain logic
- `database` - Migrations and seed data
- `docker-compose.yml` - Local PostgreSQL runtime

## Quick Start

### Prerequisites

- Node.js 18+
- Go 1.22+
- Docker Desktop

### Run Locally

```bash
docker compose up -d
cd backend && go run ./cmd/api
cd ../frontend && npm install && npm run dev
```

### Local Endpoints

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8080`
- Health: `http://localhost:8080/health`

## Demo Access

- Admin Email: `admin@securebounty.local`
- Admin Password: `Admin123!`

## API Snapshot

- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `GET /api/v1/findings`
- `POST /api/v1/findings`
- `POST /api/v1/findings/{id}/triage`
- `GET /api/v1/audit-logs`

## Screenshots Checklist

- [ ] Login / Register screen
- [ ] Dashboard overview
- [ ] Findings management
- [ ] Triage workflow
- [ ] Audit logs

## Project Status

Active portfolio project with production-minded structure and ongoing improvements to security workflows and platform reliability.

## CI

- GitHub Actions runs backend and frontend build checks on every push and pull request.
- This helps catch broken changes early before they reach main.
- CI also runs lightweight dependency security checks with `govulncheck` (Go) and `npm audit` (frontend).
- CI also runs backend tests and a secret scan to catch leaked credentials early.

## License

MIT
