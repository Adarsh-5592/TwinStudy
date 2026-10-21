# TwinStudy — Release Tracker

## Verified for v6 release candidate

- [x] 18 dependency-free release checks passed at the start of this work batch.
- [x] Python compilation passed for `server.py`, `db_manager.py`, `ai_service.py`, and `api/index.py`.
- [x] MariaDB connection and relational schema initialization succeeded.
- [x] OTP digest persistence verified against MariaDB.
- [x] OTP attempt decrement verified against MariaDB.
- [x] Temporary OTP test record deleted successfully.
- [x] Registration OTP endpoint tested using a simulated email sender.
- [x] Incorrect OTP rejected with HTTP 400 and attempt count reduced from 5 to 4.
- [x] No valid OTP submitted in the registration smoke test.

## Remaining blockers — do not mark complete yet

- [ ] Migrate remaining JSON-backed academic/application state to durable relational storage.
- [ ] Complete live/staging audit of API authentication, role enforcement, and record ownership (local route and ownership regressions are now covered).
- [x] Verify registration OTP success and password-reset revocation using disposable SQLite accounts; concurrent successful OTP consumption is covered locally.
- [ ] Complete provider-level Google sign-in, real email delivery, and MySQL/MariaDB concurrent-verification tests (OTP resend, expiry, attempt exhaustion, and stale challenge behavior are covered on isolated SQLite).
- [x] Test student task/academic CRUD and cross-student denial using disposable SQLite accounts.
- [x] Test parent link request, approval, revocation, and parent data isolation using disposable SQLite accounts.
- [ ] Verify real email delivery using properly configured provider credentials.
- [ ] Verify all required production environment variables without printing secret values.
- [ ] Verify Vercel/runtime compatibility and managed database connectivity.
- [ ] Add database backup/restore and migration validation procedures.
- [ ] Perform a clean deployment smoke test before considering production use.
- [ ] Confirm no `.env`, credentials, database dumps, user data, logs, or backups are tracked.
- [ ] Push source to a dedicated GitHub release branch and review the resulting diff.
- [ ] Configure hosting integration and deploy only after blockers are addressed.

## Active implementation batch

- [x] Classify all API endpoints as public, student-only, parent-only, operator-only, or shared-session; unclassified routes default to denied.
- [x] Apply resolved target authorization in the direct-dispatch serverless gateway.
- [x] Restrict SMTP status/configuration/test-email routes to operator role.
- [x] Mask parent dashboard summaries and details when the matching student permission is disabled; remove fabricated dashboard fallbacks.
- [x] Preserve a student's existing tasks when saving academic subjects/profile; seed suggested tasks only when no task exists.
- [x] Return accurate not-found and service-unavailable results for exam/goal mutations.
- [x] Add route-policy, parent-visibility, ownership, academic-save preservation, gateway, and cross-student CRUD regression tests.
- [x] Add per-student academic/calendar revision checks; make profile, subject-target, and collection writes share transaction locks; test stale writes, first-write races, snapshot consistency, rollback, and revision scoping on disposable SQLite.
- [x] Inventory compatibility-state fields and document migration safeguards and unresolved mappings.
- [x] Remove the unsafe legacy JSON importer body and make its old entry point fail closed; it had no dry-run, backup, or duplicate/conflict safeguards.
- [x] Make password replacement and session revocation one transaction; add rollback coverage for revocation failure.
- [x] Validate and consume successful OTPs under a database lock so concurrent verification can succeed only once.
- [x] Scope failed-attempt decrements and expiry cleanup to the OTP digest and purpose observed by that request, preventing stale requests from changing or deleting a resent challenge.
- [x] Restrict locally saved SMTP credential files to owner-only POSIX permissions and cover this with a disposable-file check.
- [ ] Implement a separate migration runner with dry-run, provider backup/restore verification, duplicate-safe repeat passes, and field validation. No protected source copy or isolated staging database is present; migration was not executed and production reads/writes remain unchanged.

Latest local results: 56 focused regression tests passed using the temporary test environment and disposable SQLite DB; all 19 dependency-free release checks passed; Python compilation, frontend-copy comparison, and `git diff --check` passed. Successful OTP consumption is one-time under concurrency; OTP expiry, incorrect attempts, exhaustion, resend, and stale-request races are covered locally. Password reset credential replacement and session revocation roll back together. Task generation preserves saved progress; academic and calendar writes use per-student optimistic revisions and reject stale collections with HTTP 409. The MySQL `FOR UPDATE` paths were source-reviewed, but live MySQL/MariaDB concurrency tests still require staging. Production database migration and backup/restore validation still require a protected source copy and isolated staging database. Google sign-in and real SMTP delivery remain unverified pending provider configuration and credentials.

## Current status

**Validation candidate, not production-ready.** Passing static checks and OTP smoke tests covers only the listed behaviors; it does not certify the entire application.
