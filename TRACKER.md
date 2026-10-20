# TwinStudy — Release Tracker

## Verified for v6 release candidate

- [x] 17 dependency-free release checks passed on the user's validation copy.
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
- [ ] Audit every API endpoint for authentication, role enforcement, and record ownership.
- [ ] Run registration success and failure tests with isolated disposable accounts.
- [ ] Test login, Google sign-in, password reset, OTP resend, expiry, attempt exhaustion, and concurrent verification.
- [ ] Test student task/academic CRUD and ensure cross-student access is denied.
- [ ] Test parent link request, approval, revocation, and parent data isolation.
- [ ] Verify real email delivery using properly configured provider credentials.
- [ ] Verify all required production environment variables without printing secret values.
- [ ] Verify Vercel/runtime compatibility and managed database connectivity.
- [ ] Add database backup/restore and migration validation procedures.
- [ ] Perform a clean deployment smoke test before considering production use.
- [ ] Confirm no `.env`, credentials, database dumps, user data, logs, or backups are tracked.
- [ ] Push source to a dedicated GitHub release branch and review the resulting diff.
- [ ] Configure hosting integration and deploy only after blockers are addressed.

## Current status

**Validation candidate, not production-ready.** Passing static checks and OTP smoke tests covers only the listed behaviors; it does not certify the entire application.
