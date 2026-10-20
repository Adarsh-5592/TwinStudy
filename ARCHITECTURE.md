# TwinStudy — Architecture

## Current release-candidate structure

```text
Browser
  ├── index.html / public/index.html
  └── HTTP requests
        ↓
Flask application (server.py)
  ├── Authentication and role-aware API routes
  ├── Academic/productivity endpoints
  ├── AI service integration (ai_service.py)
  └── Relational database manager (db_manager.py)
        ↓
MySQL / MariaDB
  └── verification_otps and other relational tables

Vercel entry point: api/index.py
Routing/runtime configuration: vercel.json
```

## Components

- **Frontend:** `index.html` and `public/index.html`. The release checks require the copies to remain synchronized.
- **API/server:** `server.py` contains Flask routes, authentication handling, and application behavior.
- **Database layer:** `db_manager.py` initializes and accesses the relational schema.
- **AI integration:** `ai_service.py` provides AI service functionality; provider configuration must be supplied outside source control.
- **Serverless entry:** `api/index.py` adapts the application for the configured hosting entry point.
- **Release validation:** `RELEASE_CHECKS.py` performs static checks; it is not a substitute for live integration tests.

## OTP data flow

1. Registration creates a verification code.
2. The application hashes the code before persistence.
3. The digest and pending verification data are stored in the relational `verification_otps` table.
4. Verification checks expiry and digest, and decrements remaining attempts atomically for incorrect codes.
5. A failed email send invalidates the pending OTP.
6. API responses must not expose clear OTPs.

## Current persistence limitation

Not all academic/application state is relational yet. The release candidate still uses `twin_database.json` for some legacy state. A local JSON file or serverless temporary filesystem is not a durable shared database and must not be treated as production storage for multi-instance deployment.

## Target production architecture

```text
Browser
   ↓ HTTPS
Managed Flask hosting / serverless runtime
   ├── Server-side authentication and ownership checks
   ├── AI provider via server-side secret
   └── Managed MySQL-compatible database
         ├── Users and role profiles
         ├── Tasks and academic records
         ├── Parent/student approvals
         ├── OTP verification records
         └── Audit/event records as required
```

The target diagram is a recommendation, not a claim that all tables or flows already exist.

## Deployment requirements

- Configure all required environment variables in the hosting provider's secret settings.
- Use a managed MySQL-compatible database reachable from the deployment runtime.
- Do not rely on ephemeral local storage for user state.
- Use database migrations and tested backups.
- Verify the serverless entry point and runtime compatibility on the target host.
- Run authorization, concurrency, and end-to-end tests before allowing real student data.
