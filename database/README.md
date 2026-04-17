# Database Setup

## Requirements

- Docker Desktop
- psql client (optional, for manual execution)

## Start PostgreSQL

From project root:

`docker compose up -d`

Use this host port for GUI tools (DBeaver/pgAdmin):

- host: `localhost`
- port: `55432`
- database: `secure_bounty`
- username: `postgres`
- password: `postgres`

## Run Migration and Seed (PowerShell)

`Get-Content .\database\migrations\001_init.sql | docker exec -i secure_bounty_postgres psql -U postgres -d secure_bounty`

`Get-Content .\database\migrations\002_security_stack.sql | docker exec -i secure_bounty_postgres psql -U postgres -d secure_bounty`

`Get-Content .\database\seeds\001_seed.sql | docker exec -i secure_bounty_postgres psql -U postgres -d secure_bounty`

## Stop Database

`docker compose down`
