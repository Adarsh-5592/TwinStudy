"""Dependency-free release checks for TwinStudy source invariants.

Run with: python RELEASE_CHECKS.py
These checks are static and do not replace integration/security testing.
"""
from pathlib import Path
import ast
import json
import re
import unittest

ROOT = Path(__file__).resolve().parent

class ReleaseChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = (ROOT / "server.py").read_text(encoding="utf-8")
        cls.db_manager = (ROOT / "db_manager.py").read_text(encoding="utf-8")

    def test_python_sources_compile(self):
        for name in ("server.py", "db_manager.py", "ai_service.py", "api/index.py", "authorization.py", "parent_visibility.py"):
            source = (ROOT / name).read_text(encoding="utf-8")
            compile(source, name, "exec")

    def test_vercel_json_parses(self):
        json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))

    def test_frontend_copies_match(self):
        self.assertEqual((ROOT / "index.html").read_bytes(), (ROOT / "public/index.html").read_bytes())

    def test_frontend_stale_revision_recovery_preserves_drafts(self):
        frontend = (ROOT / "index.html").read_text(encoding="utf-8")
        helper_start = frontend.index("const refreshRevisionTokens = async () => {")
        helper_end = frontend.index("const notifyStaleDraft = async", helper_start)
        helper = frontend[helper_start:helper_end]
        self.assertIn("academic_revision: latest.academic_revision", helper)
        self.assertIn("calendar_revision: latest.calendar_revision", helper)
        for draft_setter in ("setAcademicProfile", "setSubjectsList", "setClassesList", "fetchState"):
            self.assertNotIn(draft_setter, helper)
        self.assertEqual(frontend.count('data.code === "stale_revision"'), 3)
        self.assertEqual(frontend.count('calendarResult.code === "stale_revision"'), 1)
        self.assertIn("Your draft is still here; review it and save again.", frontend)

    def test_otp_retrieval_endpoint_never_returns_code(self):
        start = self.server.index('def auth_get_code():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end if end != -1 else None]
        self.assertIn('410', body)
        self.assertNotRegex(body, r'return\s+jsonify\(.*\bcode\b')

    def test_academic_save_requires_authenticated_student(self):
        start = self.server.index('def save_academic():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end if end != -1 else None]
        self.assertIn('if not user or user.get("role") not in ("student", "student_adult", "student_minor")', body)
        self.assertNotIn('db_mgr.get_user_by_email(email)', body)

    def test_task_create_and_generate_require_session(self):
        for function in ('def create_student_task():', 'def generate_student_tasks():'):
            start = self.server.index(function)
            end = self.server.find('\n@app.route', start)
            body = self.server[start:end if end != -1 else None]
            self.assertIn('if not user or user.get("role") not in ("student", "student_adult", "student_minor")', body)
            self.assertNotIn('db_mgr.get_user_by_email(email)', body)

    def test_parent_settings_requires_student_session(self):
        start = self.server.index('def get_student_parent_settings():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end if end != -1 else None]
        self.assertIn('get_auth_user(request)', body)
        self.assertIn('return jsonify({"status": "error", "message": "A signed-in student session is required."}), 401', body)

    def test_state_cas_and_otp_db_methods_exist(self):
        for token in ('def save_application_state(', 'version = version + 1', 'def save_otp(', 'def get_otp(', 'def delete_otp('):
            self.assertIn(token, self.db_manager)

    def test_otp_attempts_are_decremented_atomically(self):
        self.assertIn('def decrement_otp_attempts(', self.db_manager)
        self.assertIn('attempts_left = CASE WHEN attempts_left > 0 THEN attempts_left - 1 ELSE 0 END', self.db_manager)
        self.assertIn('def decrement_attempts(', self.server)
        self.assertGreaterEqual(self.server.count('verification_codes.decrement_attempts('), 2)

    def test_invalid_otp_expiry_fails_closed(self):
        start = self.db_manager.index('def get_otp(')
        end = self.db_manager.find('def decrement_otp_attempts(', start)
        body = self.db_manager[start:end]
        self.assertIn('self.delete_otp(email, stored_code, row.get("purpose"))', body)
        self.assertIn('except (TypeError, ValueError):', body)

    def test_otp_never_returned_in_development_password_reset(self):
        start = self.server.index('def forgot_send_otp():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end]
        self.assertNotIn('Local development OTP', body)
        self.assertNotIn('Local development OTP: {otp}', body)

    def test_failed_email_delivery_invalidates_registration_otp(self):
        start = self.server.index('def register_send_otp():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end]
        self.assertIn('code_digest=hashlib.sha256(otp.encode("utf-8")).hexdigest(), purpose="register"', body)
        self.assertNotIn('verification_codes.pop(email, None)', body)


    def test_production_never_allows_sqlite_fallback(self):
        self.assertIn('if is_production and not has_explicit_mysql:', self.db_manager)
        self.assertIn('if is_production:', self.db_manager)
        self.assertIn('SQLite fallback is never permitted in production.', self.db_manager)
        self.assertIn('Production requires shared MySQL; local JSON/SQLite fallback is disabled.', self.server)

    def test_state_owner_never_uses_request_email_as_identity(self):
        start = self.server.index('def _current_state_owner():')
        end = self.server.find('\ndef _request_state_key', start)
        body = self.server[start:end]
        self.assertIn('get_auth_user(request)', body)
        self.assertNotIn('get_user_by_email', body)
        self.assertNotIn('payload.get("email")', body)

    def test_twin_routes_require_student_session(self):
        for function in ('def get_twin_health():', 'def log_twin_decision():', 'def submit_twin_feedback():'):
            start = self.server.index(function)
            end = self.server.find('\n@app.route', start)
            body = self.server[start:end]
            self.assertIn('get_auth_user(request)', body)
            self.assertIn('A signed-in student session is required.', body)

    def test_twin_feedback_checks_decision_owner(self):
        start = self.server.index('def submit_twin_feedback():')
        end = self.server.find('\n@app.route', start)
        body = self.server[start:end]
        self.assertIn('str(d.get("user_id", "")) == str(user["id"])', body)

    def test_no_actual_env_or_local_database_in_release(self):
        self.assertFalse((ROOT / '.env').exists())
        excluded_dirs = {'.git', '.venv', '__pycache__'}
        local_runtime_dbs = {'twin_relational.db'}
        for p in ROOT.rglob('*'):
            if not p.is_file():
                continue
            if any(part in excluded_dirs for part in p.relative_to(ROOT).parts):
                continue
            if p.name in local_runtime_dbs and p.parent == ROOT:
                continue
            self.assertNotIn(
                p.suffix.lower(),
                {'.db', '.sqlite', '.sqlite3'},
                f"Unexpected database file in release: {p.relative_to(ROOT)}",
            )


    def test_registration_compatibility_state_is_scoped_and_owner_is_always_cleared(self):
        start = self.server.index("def register_verify_otp():")
        end = self.server.index('@app.route("/api/auth/get-code"', start)
        body = self.server[start:end]
        self.assertIn("_STATE_CONTEXT.forced_owner = db_user", body)
        self.assertEqual(body.count('"id": db_user["id"]'), 2)
        self.assertIn("finally:", body)
        self.assertIn("_STATE_CONTEXT.forced_owner = None", body)
        self.assertIn("Registration finalization failed after account creation", body)
        self.assertIn("Your account was created, but setup could not be completed", body)
        self.assertIn('verification_codes.consume(email, "register", submitted_code_hash)', body)
        self.assertNotIn('verification_codes.pop(email, None)', body)

if __name__ == '__main__':
    unittest.main(verbosity=2)
