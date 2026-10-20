# TwinStudy

TwinStudy is a Flask-based student productivity and academic-support web application. This release candidate includes student/parent dashboards, Google Identity Services sign-in configuration, academic productivity features, and relational database support for OTP verification.

## Current release status

**Status: validation candidate — not approved for production student data.**

The v6 release has passed 17 dependency-free release checks and Python compilation. Local MariaDB smoke tests also verified OTP digest persistence, atomic attempt decrement, and the registration endpoint's handling of an incorrect OTP using a simulated email sender.

These tests do not establish that every authentication path, academic CRUD route, multi-instance deployment, or email-delivery workflow is production-ready.

## Included files

- `server.py` — Flask application and API routes.
- `db_manager.py` — relational database operations and schema initialization.
- `ai_service.py` — AI service integration.
- `api/index.py` — serverless entry point.
- `public/index.html` and `index.html` — frontend copies.
- `RELEASE_CHECKS.py` — static release checks.
- `vercel.json` — Vercel routing/runtime configuration.
- `.env.example` — environment-variable names/placeholders; no real secrets should be committed.

## Local setup

1. Use a supported Python version compatible with `requirements.txt`.
2. Create and activate a virtual environment.
3. Install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. Create/configure a local environment file from `.env.example`. Set database credentials and required authentication, AI, and email configuration locally. Never commit `.env`.
5. Ensure the configured MySQL/MariaDB database exists and the application database user has only the required privileges.
6. Run the release checks:

   ```bash
   python RELEASE_CHECKS.py
   python -m py_compile server.py db_manager.py ai_service.py api/index.py
   ```

7. Start the Flask app using the project's documented entry point and verify the login and academic flows with disposable test accounts before use.

Exact environment-variable requirements and the hosting runtime must be checked against the deployed code and target provider before deployment.

## Database and data safety

OTP records use the relational `verification_otps` table and store a SHA-256 digest rather than the clear OTP. OTP expiry validation fails closed for malformed or expired timestamps, and failed-code attempts are decremented in the database.

**Important limitation:** legacy academic/task/grade application state is still partly backed by `twin_database.json` compatibility state. OTP persistence does not mean all student data has been migrated to MySQL or made safe for multi-instance hosting. Do not use real student data until state migration, authorization/data-ownership review, backups, and multi-instance tests are complete.

## Security rules

- Never commit `.env`, real credentials, database files, student records, logs, or backups.
- Use HTTPS and a managed MySQL-compatible database in production.
- Configure secrets through the hosting provider's environment-variable settings.
- Verify that every academic route enforces authentication and ownership checks.
- Keep parent access restricted to authenticated parents and approved student relationships.
- Do not expose OTPs or other verification secrets through API responses or logs.

## Deployment blockers

Before production:
- Migrate remaining JSON-backed academic/application state to durable, user-scoped relational tables.
- Complete endpoint-by-endpoint authorization and data-ownership review.
- Run end-to-end tests for registration, login, Google sign-in, password reset, OTP resend/expiry/attempt limits, student academic CRUD, parent approval/revocation, and concurrent requests.
- Verify required production environment variables and real email delivery without exposing secrets.
- Test deployment on the actual hosting platform with a managed database and backup/restore procedure.
