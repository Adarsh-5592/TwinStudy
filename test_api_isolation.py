"""Flask/database regression coverage using a disposable copied app and SQLite DB."""
import importlib
import importlib.util
import datetime
import io
import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent


@unittest.skipUnless(
    all(importlib.util.find_spec(module) for module in ("flask", "pymysql", "werkzeug", "dotenv")),
    "Flask/PyMySQL/Werkzeug/dotenv dependencies are required for isolated API integration tests",
)
class ApiIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="twinstudy-isolated-")
        cls.app_root = Path(cls.temp.name)
        for filename in ("server.py", "db_manager.py", "ai_service.py", "authorization.py", "parent_visibility.py"):
            shutil.copy2(ROOT / filename, cls.app_root / filename)
        (cls.app_root / "public").mkdir()
        cls.env = patch.dict(os.environ, {
            "DATABASE_URL": "", "MYSQL_URL": "", "MYSQL_HOST": "",
            "MYSQL_PASSWORD": "", "VERCEL": "", "IS_VERCEL": "",
            "ENVIRONMENT": "test", "NODE_ENV": "test", "FLASK_ENV": "development",
            "ALLOW_SQLITE_FALLBACK": "true",
        })
        cls.env.start()
        sys.path.insert(0, str(cls.app_root))
        cls.server = importlib.import_module("server")
        cls.db = cls.server.db_mgr
        cls.client = cls.server.app.test_client()
        cls.users = {}
        for key, role in (("student_a", "student"), ("student_b", "student"), ("parent", "parent")):
            user, error = cls.db.create_user(
                f"{key}@example.test", "Disposable-Password-42!", key, role=role
            )
            if error:
                raise AssertionError(error)
            cls.users[key] = user
            cls.users[key]["token"] = cls.db.create_session(user["id"])

    @classmethod
    def tearDownClass(cls):
        for name in ("server", "db_manager", "ai_service", "authorization"):
            sys.modules.pop(name, None)
        if str(cls.app_root) in sys.path:
            sys.path.remove(str(cls.app_root))
        cls.env.stop()
        cls.temp.cleanup()

    def auth(self, key):
        return {"Authorization": f"Bearer {self.users[key]['token']}"}

    def current_revisions(self, auth):
        response = self.client.get("/api/state", headers=auth)
        self.assertEqual(response.status_code, 200, response.get_json())
        state = response.get_json()
        return state["academic_revision"], state["calendar_revision"]

    def test_session_alone_does_not_allow_parent_student_or_smtp_routes(self):
        for path, method, body in (
            ("/api/grades", "get", None),
            ("/api/student/update-profile", "post", {}),
            ("/api/auth/configure-smtp", "post", {"sender_email": "x", "sender_password": "x"}),
            ("/api/auth/test-smtp", "post", {"test_email": "x@example.test"}),
            ("/api/auth/smtp-status", "get", None),
        ):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path, headers=self.auth("parent"), json=body)
                self.assertEqual(response.status_code, 403)

    def test_student_cannot_call_parent_only_routes(self):
        link_response = self.client.post(
            "/api/parent/link-student", headers=self.auth("student_a"), json={"student_email": "other@example.test"}
        )
        dashboard_response = self.client.get(
            "/api/parent/dashboard-data", headers=self.auth("student_a")
        )
        self.assertEqual(link_response.status_code, 403)
        self.assertEqual(dashboard_response.status_code, 403)

    def test_registration_otp_success_creates_user_without_returning_the_code(self):
        email = f"register-{uuid.uuid4().hex}@example.test"
        sent_codes = []

        def fake_send(_to, _subject, code, **_kwargs):
            sent_codes.append(code)
            return True, "simulated"

        with patch.object(self.server, "send_email_via_smtp", side_effect=fake_send):
            sent = self.client.post("/api/auth/register-send-otp", json={
                "role": "student", "name": "Disposable student", "email": email,
                "dob": "2000-01-01", "age": 26,
                "password": "Disposable-Password-42!", "confirm_password": "Disposable-Password-42!",
            })
        self.assertEqual(sent.status_code, 200, sent.get_json())
        self.assertNotIn("code", sent.get_json())
        self.assertEqual(len(sent_codes), 1)
        verified = self.client.post("/api/auth/register-verify-otp", json={
            "email": email, "code": sent_codes[0],
        })
        self.assertEqual(verified.status_code, 200, verified.get_json())
        self.assertEqual(self.db.get_user_by_email(email)["email"], email)
        self.assertIsNone(self.db.get_otp(email))

    def test_password_reset_revokes_existing_sessions(self):
        user, error = self.db.create_user(
            f"reset-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Reset student", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        code = "481529"
        self.server.verification_codes[user["email"]] = {
            "code": code, "purpose": "forgot", "email": user["email"],
            "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
        }
        response = self.client.post("/api/auth/forgot-verify-otp", json={
            "email": user["email"], "code": code,
            "new_password": "New-Disposable-Password-87!",
            "confirm_password": "New-Disposable-Password-87!",
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code, 401)
        login = self.client.post("/api/auth/login", json={
            "email": user["email"], "password": "New-Disposable-Password-87!",
        })
        self.assertEqual(login.status_code, 200, login.get_json())

    def test_login_keeps_case_insensitive_linking_code_behavior(self):
        user, error = self.db.create_user(
            f"link-code-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Link code student",
            role="student", linking_code="TS-LINK-AbCd",
        )
        self.assertIsNone(error)
        response = self.client.post("/api/auth/login", json={
            "identifier": "ts-link-abcd", "password": "Disposable-Password-42!",
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["user"]["id"], user["id"])

    def test_login_prefers_email_when_it_matches_another_accounts_linking_code(self):
        collision = f"collision-{uuid.uuid4().hex}@example.test"
        code_owner, error = self.db.create_user(
            f"code-owner-{uuid.uuid4().hex}@example.test", "Other-Disposable-Password-88!", "Code owner",
            role="student", linking_code=collision,
        )
        self.assertIsNone(error)
        email_owner, error = self.db.create_user(
            collision, "Disposable-Password-42!", "Email owner", role="student",
        )
        self.assertIsNone(error)
        response = self.client.post("/api/auth/login", json={
            "identifier": collision, "password": "Disposable-Password-42!",
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["user"]["id"], email_owner["id"])
        self.assertNotEqual(response.get_json()["user"]["id"], code_owner["id"])

    def test_login_session_is_revoked_when_password_reset_races_verified_login(self):
        user, error = self.db.create_user(
            f"login-reset-race-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Race student", role="student"
        )
        self.assertIsNone(error)
        verified_old_password = threading.Event()
        finish_login = threading.Event()
        reset_started = threading.Event()
        reset_finished = threading.Event()
        original_check = __import__("db_manager").check_password_hash
        original_create_session = self.db.create_session

        def pause_after_password_check(password_hash, password):
            result = original_check(password_hash, password)
            if result:
                verified_old_password.set()
                self.assertTrue(finish_login.wait(5), "test did not release login")
            return result

        def login():
            with self.server.app.test_client() as isolated_client:
                return isolated_client.post("/api/auth/login", json={
                    "email": user["email"], "password": "Disposable-Password-42!",
                })

        def reset():
            reset_started.set()
            try:
                return self.db.reset_user_password_and_revoke_sessions(
                    user["id"], "New-Disposable-Password-87!"
                )
            finally:
                reset_finished.set()

        def create_session_after_reset(user_id):
            # The old split login path reaches this call after checking the
            # password. Hold its session insert until reset has committed so the
            # regression test forces the vulnerable ordering deterministically.
            self.assertTrue(reset_finished.wait(5), "password reset did not finish before session creation")
            return original_create_session(user_id)

        with patch("db_manager.check_password_hash", side_effect=pause_after_password_check), \
             patch.object(self.db, "create_session", side_effect=create_session_after_reset):
            with ThreadPoolExecutor(max_workers=2) as pool:
                login_future = pool.submit(login)
                self.assertTrue(verified_old_password.wait(5), "login did not verify the old password")
                reset_future = pool.submit(reset)
                self.assertTrue(reset_started.wait(5), "reset did not start while login was paused")
                finish_login.set()
                response = login_future.result(timeout=10)
                reset_future.result(timeout=10)
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json()["token"]
        self.assertIsNone(self.db.get_user_by_token(token))
        self.assertIsNone(self.db.verify_user_login(user["email"], "Disposable-Password-42!")[0])
        self.assertIsNotNone(self.db.verify_user_login(user["email"], "New-Disposable-Password-87!")[0])

    def test_login_route_uses_atomic_authentication_instead_of_split_calls(self):
        user, error = self.db.create_user(
            f"atomic-login-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Atomic login", role="student"
        )
        self.assertIsNone(error)
        with patch.object(self.db, "verify_user_login", side_effect=AssertionError("legacy split login called")), \
             patch.object(self.db, "create_session", side_effect=AssertionError("separate session insert called")):
            response = self.client.post("/api/auth/login", json={
                "email": user["email"], "password": "Disposable-Password-42!",
            })
        self.assertEqual(response.status_code, 200, response.get_json())

    def test_successful_otp_cleanup_does_not_delete_a_resend_challenge(self):
        user, error = self.db.create_user(
            f"otp-reset-resend-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "OTP race", role="student"
        )
        self.assertIsNone(error)
        old_code = "481529"
        new_code = "735184"
        self.server.verification_codes[user["email"]] = {
            "code": old_code, "purpose": "forgot", "email": user["email"], "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
        }
        original_reset = self.db.reset_user_password_and_revoke_sessions

        def reset_then_resend(user_id, new_password):
            self.server.verification_codes[user["email"]] = {
                "code": new_code, "purpose": "forgot", "email": user["email"], "attempts_left": 5,
                "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            }
            return original_reset(user_id, new_password)

        with patch.object(self.db, "reset_user_password_and_revoke_sessions", side_effect=reset_then_resend):
            response = self.client.post("/api/auth/forgot-verify-otp", json={
                "email": user["email"], "code": old_code,
                "new_password": "New-Disposable-Password-87!",
                "confirm_password": "New-Disposable-Password-87!",
            })
        self.assertEqual(response.status_code, 200, response.get_json())
        current = self.db.get_otp(user["email"])
        self.assertEqual(current["code"], __import__("hashlib").sha256(new_code.encode()).hexdigest())

    def test_expiry_and_attempt_cleanup_only_remove_the_challenge_that_was_read(self):
        digest = __import__("hashlib").sha256
        for purpose, branch in (("register", "expired"), ("register", "exhausted"),
                                ("forgot", "expired"), ("forgot", "exhausted")):
            with self.subTest(purpose=purpose, branch=branch):
                email = f"otp-cleanup-{purpose}-{branch}-{uuid.uuid4().hex}@example.test"
                old_code, new_code = "481529", "735184"
                old_expiry = (datetime.datetime.now() - datetime.timedelta(minutes=1)
                              if branch == "expired" else datetime.datetime.now() + datetime.timedelta(minutes=5))
                captured = {
                    "code": old_code, "purpose": purpose, "email": email,
                    "attempts_left": 0 if branch == "exhausted" else 5,
                    "expires_at": old_expiry.isoformat(),
                }
                resent = {
                    "code": new_code, "purpose": purpose, "email": email, "attempts_left": 5,
                    "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
                }
                read_once = {"done": False}
                original_get = self.server.verification_codes.get

                def read_then_resend(requested_email, default=None):
                    if requested_email == email and not read_once["done"]:
                        read_once["done"] = True
                        self.server.verification_codes[email] = resent
                        return captured
                    return original_get(requested_email, default)

                path = "/api/auth/register-verify-otp" if purpose == "register" else "/api/auth/forgot-verify-otp"
                body = {"email": email, "code": old_code}
                if purpose == "forgot":
                    body.update({"new_password": "New-Disposable-Password-87!",
                                 "confirm_password": "New-Disposable-Password-87!"})
                with patch.object(self.server.verification_codes, "get", side_effect=read_then_resend):
                    response = self.client.post(path, json=body)
                self.assertEqual(response.status_code, 400, response.get_json())
                current = self.db.get_otp(email)
                self.assertEqual(current["code"], digest(new_code.encode()).hexdigest())

    def test_delivery_failure_cleanup_does_not_remove_a_newer_challenge(self):
        digest = __import__("hashlib").sha256

        def replace_during_delivery(email, purpose):
            newer_code = "735184"

            def fail_after_resend(_to, _subject, _sent_code, **_kwargs):
                self.server.verification_codes[email] = {
                    "code": newer_code, "purpose": purpose, "email": email, "attempts_left": 5,
                    "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
                }
                return False, "simulated delivery failure"
            return newer_code, fail_after_resend

        register_email = f"register-delivery-race-{uuid.uuid4().hex}@example.test"
        newer_code, sender = replace_during_delivery(register_email, "register")
        with patch.object(self.server, "send_email_via_smtp", side_effect=sender):
            registration = self.client.post("/api/auth/register-send-otp", json={
                "role": "student", "name": "Disposable", "email": register_email,
                "dob": "2000-01-01", "age": 26,
                "password": "Disposable-Password-42!", "confirm_password": "Disposable-Password-42!",
            })
        self.assertEqual(registration.status_code, 400)
        self.assertEqual(self.db.get_otp(register_email)["code"], digest(newer_code.encode()).hexdigest())

        reset_user, error = self.db.create_user(
            f"forgot-delivery-race-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Reset user", role="student"
        )
        self.assertIsNone(error)
        newer_code, sender = replace_during_delivery(reset_user["email"], "forgot")
        with patch.object(self.server, "send_email_via_smtp", side_effect=sender):
            forgot = self.client.post("/api/auth/forgot-send-otp", json={"email": reset_user["email"]})
        self.assertEqual(forgot.status_code, 503)
        self.assertEqual(self.db.get_otp(reset_user["email"])["code"], digest(newer_code.encode()).hexdigest())

        resend_email = f"resend-delivery-race-{uuid.uuid4().hex}@example.test"
        self.server.verification_codes[resend_email] = {
            "code": "481529", "purpose": "register", "email": resend_email, "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            "last_sent_at": (datetime.datetime.now() - datetime.timedelta(minutes=2)).isoformat(),
        }
        newer_code, sender = replace_during_delivery(resend_email, "register")
        with patch.object(self.server, "send_email_via_smtp", side_effect=sender):
            resent = self.client.post("/api/auth/resend-otp", json={"email": resend_email, "purpose": "register"})
        self.assertEqual(resent.status_code, 400)
        self.assertEqual(self.db.get_otp(resend_email)["code"], digest(newer_code.encode()).hexdigest())

    def test_registration_completion_does_not_delete_a_newer_otp_challenge(self):
        email = f"register-resend-race-{uuid.uuid4().hex}@example.test"
        old_code = "481529"
        new_code = "735184"
        self.server.verification_codes[email] = {
            "code": old_code, "purpose": "register", "email": email, "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            "data": {
                "role": "student", "name": "OTP race student", "email": email,
                "dob": "2000-01-01", "age": 26,
                "password_hash": __import__("werkzeug.security", fromlist=["generate_password_hash"]).generate_password_hash("Disposable-Password-42!"),
                "is_minor": False,
            },
        }
        original_create = self.db.create_user

        def create_then_resend(*args, **kwargs):
            result = original_create(*args, **kwargs)
            self.server.verification_codes[email] = {
                "code": new_code, "purpose": "register", "email": email, "attempts_left": 5,
                "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            }
            return result

        with patch.object(self.db, "create_user", side_effect=create_then_resend):
            response = self.client.post("/api/auth/register-verify-otp", json={"email": email, "code": old_code})
        self.assertEqual(response.status_code, 200, response.get_json())
        current = self.db.get_otp(email)
        self.assertEqual(current["code"], __import__("hashlib").sha256(new_code.encode()).hexdigest())

    def test_password_reset_rolls_back_credential_change_if_revocation_fails(self):
        user, error = self.db.create_user(
            f"reset-rollback-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Reset student", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        old_hash = self.db.get_user_by_id(user["id"])["password_hash"]
        code = "481529"
        self.server.verification_codes[user["email"]] = {
            "code": code, "purpose": "forgot", "email": user["email"], "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
        }
        original_translate = self.db._translate_query

        def fail_session_delete(query):
            if query.startswith("DELETE FROM sessions"):
                raise RuntimeError("simulated session-revocation failure")
            return original_translate(query)

        with patch.object(self.db, "_translate_query", side_effect=fail_session_delete):
            response = self.client.post("/api/auth/forgot-verify-otp", json={
                "email": user["email"], "code": code,
                "new_password": "New-Disposable-Password-87!",
                "confirm_password": "New-Disposable-Password-87!",
            })
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.db.get_user_by_id(user["id"])["password_hash"], old_hash)
        self.assertIsNotNone(self.db.get_user_by_token(token))

    def test_successful_otp_can_only_be_consumed_once_concurrently(self):
        email = f"otp-race-{uuid.uuid4().hex}@example.test"
        code = "481529"
        digest = __import__("hashlib").sha256(code.encode("utf-8")).hexdigest()
        self.server.verification_codes[email] = {
            "code": code, "purpose": "register", "email": email,
            "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            "data": {"role": "student", "email": email},
        }
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(
                lambda _index: self.server.verification_codes.consume(email, "register", digest),
                range(2),
            ))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertIsNone(self.db.get_otp(email))

    def test_stale_wrong_otp_cannot_decrement_or_delete_resent_code(self):
        email = f"otp-resend-race-{uuid.uuid4().hex}@example.test"
        old_code = "481529"
        old_digest = __import__("hashlib").sha256(old_code.encode("utf-8")).hexdigest()
        new_code = "735184"
        new_digest = __import__("hashlib").sha256(new_code.encode("utf-8")).hexdigest()
        expires = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
        self.server.verification_codes[email] = {
            "code": old_code, "purpose": "register", "email": email,
            "attempts_left": 5, "expires_at": expires,
        }
        # The first request has already read the old challenge when resend replaces it.
        self.server.verification_codes[email] = {
            "code": new_code, "purpose": "register", "email": email,
            "attempts_left": 5, "expires_at": expires,
        }
        remaining = self.server.verification_codes.decrement_attempts(
            email, old_digest, "register"
        )
        self.assertEqual(remaining, 0)
        self.server.verification_codes.pop(
            email, None, code_digest=old_digest, purpose="register"
        )
        current = self.db.get_otp(email)
        self.assertEqual(current["code"], new_digest)
        self.assertEqual(int(current["attempts_left"]), 5)

    def test_otp_expiry_attempt_limit_and_resend_lifecycle(self):
        expired_email = f"otp-expired-{uuid.uuid4().hex}@example.test"
        self.server.verification_codes[expired_email] = {
            "code": "481529", "purpose": "register", "email": expired_email,
            "attempts_left": 5,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            "data": {"email": expired_email, "role": "student"},
        }
        self.db.execute(
            "UPDATE verification_otps SET expires_at = %s WHERE email = %s",
            ((datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"), expired_email),
        )
        expired = self.client.post("/api/auth/register-verify-otp", json={
            "email": expired_email, "code": "481529",
        })
        self.assertEqual(expired.status_code, 400)
        self.assertIsNone(self.db.get_otp(expired_email))

        attempts_email = f"otp-attempts-{uuid.uuid4().hex}@example.test"
        self.server.verification_codes[attempts_email] = {
            "code": "481529", "purpose": "forgot", "email": attempts_email,
            "attempts_left": 2,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
        }
        for expected_remaining in (1, 0):
            wrong = self.client.post("/api/auth/forgot-verify-otp", json={
                "email": attempts_email, "code": "000000",
                "new_password": "New-Disposable-Password-87!",
                "confirm_password": "New-Disposable-Password-87!",
            })
            self.assertEqual(wrong.status_code, 400)
            self.assertIn(f"{expected_remaining} attempt(s) remaining", wrong.get_json()["message"])
        self.assertIsNone(self.db.get_otp(attempts_email))

        resend_email = f"otp-resend-{uuid.uuid4().hex}@example.test"
        previous_code = "481529"
        self.server.verification_codes[resend_email] = {
            "code": previous_code, "purpose": "register", "email": resend_email,
            "attempts_left": 3,
            "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            "last_sent_at": (datetime.datetime.now() - datetime.timedelta(minutes=2)).isoformat(),
        }
        delivered = []
        with patch.object(self.server, "send_email_via_smtp", side_effect=lambda _to, _subject, code, **_kwargs: (delivered.append(code) or True, "simulated")):
            resent = self.client.post("/api/auth/resend-otp", json={
                "email": resend_email, "purpose": "register",
            })
        self.assertEqual(resent.status_code, 200, resent.get_json())
        self.assertEqual(len(delivered), 1)
        self.assertNotEqual(delivered[0], previous_code)
        stored = self.db.get_otp(resend_email)
        self.assertEqual(stored["code"], __import__("hashlib").sha256(delivered[0].encode("utf-8")).hexdigest())
        self.assertEqual(int(stored["attempts_left"]), 5)

    def test_legacy_json_migration_entrypoint_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "Legacy JSON migration is disabled"):
            self.db.migrate_from_json_if_needed()

    @unittest.skipUnless(os.name == "posix", "POSIX file mode check")
    def test_saved_local_smtp_credentials_are_owner_readable_only(self):
        self.server.save_email_config({
            "configured": True, "sender_email": "disposable@example.test",
            "sender_password": "disposable-test-value",
        })
        saved = __import__("json").loads((self.app_root / "email_config.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["sender_email"], "disposable@example.test")
        self.assertEqual(saved["sender_password"], "disposable-test-value")
        config_mode = stat.S_IMODE((self.app_root / "email_config.json").stat().st_mode)
        env_mode = stat.S_IMODE((self.app_root / ".env").stat().st_mode)
        self.assertEqual(config_mode, 0o600)
        self.assertEqual(env_mode, 0o600)

    def test_smtp_configuration_reports_atomic_persistence_and_permission_failures(self):
        body = {"sender_email": "smtp@example.test", "sender_password": "disposable-smtp-value"}

        with patch.object(self.server, "get_auth_user", return_value={"role": "admin"}):
            with patch.object(self.server.os, "replace", side_effect=OSError("simulated replace failure")):
                failed_replace = self.client.post("/api/auth/configure-smtp", json=body)
        self.assertEqual(failed_replace.status_code, 500)
        self.assertNotIn("disposable-smtp-value", failed_replace.get_data(as_text=True))
        self.assertIn("securely saved", failed_replace.get_json()["message"])

        if os.name == "posix":
            with patch.object(self.server, "get_auth_user", return_value={"role": "admin"}):
                with patch.object(self.server.os, "fchmod", side_effect=PermissionError("simulated mode failure")):
                    failed_mode = self.client.post("/api/auth/configure-smtp", json=body)
            self.assertEqual(failed_mode.status_code, 500)
            self.assertNotIn("disposable-smtp-value", failed_mode.get_data(as_text=True))
            self.assertIn("securely saved", failed_mode.get_json()["message"])

    def test_smtp_delivery_errors_do_not_log_or_return_credentials(self):
        secret = "disposable-smtp-secret"
        output = io.StringIO()
        with patch.object(self.server, "get_email_config", return_value={
            "sender_email": "smtp@example.test", "sender_password": secret,
        }), patch.object(self.server.smtplib, "SMTP", side_effect=RuntimeError(secret)), \
             patch("sys.stdout", output):
            success, message = self.server.send_email_via_smtp(
                "student@example.test", "Test", "123456"
            )
        self.assertFalse(success)
        self.assertNotIn(secret, message)
        self.assertNotIn(secret, output.getvalue())

    def test_serverless_gateway_does_not_retry_a_mutating_handler_exception(self):
        calls = []

        def mutate_then_raise(**_kwargs):
            calls.append("called")
            raise RuntimeError("simulated handler failure")

        with patch.dict(self.server.app.view_functions, {"get_state": mutate_then_raise}):
            response = self.client.get(
                "/api/index.py?__path=state", headers=self.auth("student_a")
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(calls, ["called"])

    def test_parent_dashboard_endpoint_is_not_false_denied(self):
        response = self.client.get("/api/parent/dashboard-data", headers=self.auth("parent"))
        self.assertEqual(response.status_code, 404)
        self.assertIn("No approved student", response.get_json()["message"])

    def test_serverless_gateway_applies_target_route_policy(self):
        # Login is public and must reach the target handler through the gateway.
        for gateway in ("/index.py", "/api/index.py"):
            public_response = self.client.post(gateway + "?__path=auth/login", json={})
            self.assertEqual(public_response.status_code, 400)
        # The gateway itself must not allow a parent to invoke operator-only SMTP routes.
        blocked_response = self.client.post(
            "/api/index.py?__path=auth/configure-smtp", headers=self.auth("parent"), json={}
        )
        self.assertEqual(blocked_response.status_code, 403)
        blocked_student_response = self.client.get(
            "/api/index.py?__path=grades", headers=self.auth("parent")
        )
        self.assertEqual(blocked_student_response.status_code, 403)
        # Target routes that require a session stay protected through direct dispatch.
        unauthenticated_response = self.client.get("/api/index.py?__path=grades")
        self.assertEqual(unauthenticated_response.status_code, 401)

    def test_academic_save_uses_session_owner_when_payload_spoofs_email(self):
        academic_revision, calendar_revision = self.current_revisions(self.auth("student_a"))
        other_academic_revision, _other_calendar_revision = self.current_revisions(self.auth("student_b"))
        response = self.client.post("/api/academic/save", headers=self.auth("student_a"), json={
            "email": self.users["student_b"]["email"],
            "user_id": self.users["student_b"]["id"],
            "academic_revision": academic_revision,
            "calendar_revision": calendar_revision,
            "academic_profile": {"student_name": "Student A", "course": "Course A"},
            "subjects": [{"id": "subject-a", "name": "A subject"}],
            "classes": [],
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(
            [s["name"] for s in self.db.get_user_academic_state(self.users["student_a"]["id"])["subjects"]],
            ["A subject"],
        )
        self.assertEqual(self.db.get_user_academic_state(self.users["student_b"]["id"])["subjects"], [])
        self.assertEqual(
            self.db.get_user_data_versions(self.users["student_b"]["id"])["academic_revision"],
            other_academic_revision,
        )

    def test_document_extraction_returns_normalized_review_data(self):
        model_output = {
            "academic_profile": {"college": "Example College", "course": "Biology"},
            "subjects": [{"name": "Biology", "code": "BIO101"}],
            "classes": [{"subject": "Biology", "day": "mon", "start_time": "9:30 AM", "end_time": "11:00 AM"}],
            "exams": [{"title": "Midterm", "subject_name": "Biology", "exam_date": "2026-11-02"}],
            "calendar_events": [{"title": "Term begins", "event_date": "2026-10-26"}],
            "uncertain_items": [],
        }

        class ModelResponse:
            ok = True
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {"candidates": [{"content": {"parts": [{"text": json.dumps(model_output)}]}}]}

        with patch.dict(os.environ, {"GEMINI_API_KEY": "disposable-test-key"}), \
             patch("requests.post", return_value=ModelResponse()):
            response = self.client.post(
                "/api/academic/extract-documents",
                headers=self.auth("student_a"),
                data={"timetable_file": (io.BytesIO(b"disposable pdf bytes"), "timetable.pdf")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        extraction = response.get_json()["extraction"]
        self.assertEqual(extraction["academic_profile"]["course"], "Biology")
        self.assertEqual(extraction["subjects"][0]["name"], "Biology")
        self.assertEqual(extraction["classes"][0]["day"], "Monday")
        self.assertEqual(extraction["classes"][0]["start_time"], "09:30")
        self.assertEqual(extraction["classes"][0]["end_time"], "11:00")
        self.assertEqual(extraction["exams"][0]["exam_date"], "2026-11-02")
        self.assertEqual(extraction["calendar_events"][0]["event_date"], "2026-10-26")

    def test_confirmed_document_import_persists_and_reloads_all_academic_records(self):
        user, error = self.db.create_user(
            f"document-import-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Import student", role="student"
        )
        self.assertIsNone(error)
        auth = {"Authorization": f"Bearer {self.db.create_session(user['id'])}"}
        academic_revision, calendar_revision = self.current_revisions(auth)
        payload = {
            "academic_revision": academic_revision,
            "calendar_revision": calendar_revision,
            "academic_profile": {"student_name": "Import student", "college": "Example College", "course": "Biology"},
            "subjects": [{"id": "import-bio", "name": "Biology", "code": "BIO101"}],
            "classes": [{"id": "import-bio-mon", "subject": "Biology", "day": "Monday", "start_time": "09:30", "end_time": "11:00", "time": "09:30 - 11:00"}],
            "exams": [{"id": "import-bio-midterm", "title": "Biology Midterm", "subject_name": "Biology", "exam_date": "2026-11-02"}],
            "calendar_events": [{"id": "import-term-start", "title": "Term begins", "event_date": "2026-10-26", "event_type": "term"}],
            "calendar_exams": [{"id": "import-calendar-midterm", "title": "Biology Midterm", "subject_name": "Biology", "exam_date": "2026-11-02"}],
        }

        imported = self.client.post("/api/academic/save", headers=auth, json=payload)
        self.assertEqual(imported.status_code, 200, imported.get_json())
        saved = self.db.get_user_academic_state(user["id"])
        self.assertEqual(saved["academic_profile"]["course"], "Biology")
        self.assertEqual([item["name"] for item in saved["subjects"]], ["Biology"])
        self.assertEqual([item["day"] for item in saved["classes"]], ["Monday"])
        self.assertEqual([item["title"] for item in saved["exams"]], ["Biology Midterm"])
        calendar = self.db.get_user_calendar(user["id"])
        self.assertEqual(calendar["calendar_events"][0]["title"], "Term begins")
        self.assertEqual(calendar["calendar_exams"][0]["title"], "Biology Midterm")

        reloaded = self.client.get("/api/state", headers=auth)
        self.assertEqual(reloaded.status_code, 200, reloaded.get_json())
        dashboard = reloaded.get_json()
        self.assertEqual(dashboard["academic_profile"]["course"], "Biology")
        self.assertEqual(len(dashboard["subjects"]), 1)
        self.assertEqual(len(dashboard["classes"]), 1)
        self.assertEqual(len(dashboard["exams"]), 1)
        self.assertEqual(len(dashboard["calendar_events"]), 1)
        self.assertEqual(len(dashboard["calendar_exams"]), 1)

        other_state = self.client.get("/api/state", headers=self.auth("student_b")).get_json()
        self.assertEqual(other_state["subjects"], [])
        self.assertEqual(other_state["classes"], [])
        self.assertEqual(other_state["exams"], [])
        self.assertEqual(other_state["calendar_events"], [])

        latest = dashboard
        repeated_payload = {**payload, "academic_revision": latest["academic_revision"],
                            "calendar_revision": latest["calendar_revision"], "exams": [],
                            "subjects": latest["subjects"], "classes": latest["classes"],
                            "calendar_events": latest["calendar_events"],
                            "calendar_exams": latest["calendar_exams"]}
        repeated = self.client.post("/api/academic/save", headers=auth, json=repeated_payload)
        self.assertEqual(repeated.status_code, 200, repeated.get_json())
        preserved = self.db.get_user_academic_state(user["id"])
        self.assertEqual(len(preserved["subjects"]), 1)
        self.assertEqual(len(preserved["classes"]), 1)
        self.assertEqual(len(preserved["exams"]), 1)
        self.assertEqual(len(self.db.get_user_calendar(user["id"])["calendar_events"]), 1)

    def test_academic_import_database_failure_is_returned_as_error(self):
        user, error = self.db.create_user(
            f"document-import-fail-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Import failure", role="student"
        )
        self.assertIsNone(error)
        auth = {"Authorization": f"Bearer {self.db.create_session(user['id'])}"}
        academic_revision, _calendar_revision = self.current_revisions(auth)
        with patch.object(self.db, "save_user_academic_state", side_effect=RuntimeError("simulated database failure")):
            response = self.client.post("/api/academic/save", headers=auth, json={
                "academic_revision": academic_revision,
                "academic_profile": {"college": "Example College", "course": "Biology"},
                "subjects": [{"id": "must-not-save", "name": "Biology"}],
                "classes": [], "exams": [],
            })
        self.assertEqual(response.status_code, 503)
        self.assertNotEqual(response.get_json().get("status"), "success")
        self.assertEqual(self.db.get_user_academic_state(user["id"])["subjects"], [])

    def test_collection_replacements_require_current_revision_tokens(self):
        academic = self.client.post("/api/academic/save", headers=self.auth("student_a"), json={
            "academic_profile": {}, "subjects": [], "classes": [],
        })
        calendar = self.client.post("/api/academic/calendar-save", headers=self.auth("student_a"), json={
            "calendar_events": [], "calendar_exams": [],
        })
        self.assertEqual(academic.status_code, 428, academic.get_json())
        self.assertEqual(calendar.status_code, 428, calendar.get_json())
        malformed = self.client.post("/api/academic/save", headers=self.auth("student_a"), json={
            "academic_revision": 1.75, "academic_profile": {}, "subjects": [], "classes": [],
        })
        self.assertEqual(malformed.status_code, 428, malformed.get_json())

    def test_profile_and_subject_target_writes_advance_the_academic_revision(self):
        user, error = self.db.create_user(
            f"revision-writers-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Revision writer", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        academic_revision, _calendar_revision = self.current_revisions(auth)
        saved = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": academic_revision,
            "academic_profile": {"student_name": "Revision writer", "course": "Course one"},
            "subjects": [{"id": "revision-subject", "name": "Revision subject", "target_grade": "B"}],
            "classes": [],
        })
        self.assertEqual(saved.status_code, 200, saved.get_json())
        stale_profile = self.client.post("/api/student/update-profile", headers=auth, json={
            "academic_revision": academic_revision, "name": "Stale profile", "course": "Stale course",
            "semester": "One", "college": "Example College", "age": 26, "daily_study_hours": 3,
        })
        self.assertEqual(stale_profile.status_code, 409, stale_profile.get_json())
        current_revision = saved.get_json()["academic_revision"]
        target = self.client.post("/api/grades/update-target", headers=auth, json={
            "academic_revision": current_revision,
            "subject_id": "revision-subject", "target_grade": "A",
        })
        self.assertEqual(target.status_code, 200, target.get_json())
        self.assertEqual(target.get_json()["academic_revision"], current_revision + 1)
        profile_saved = self.client.post("/api/student/update-profile", headers=auth, json={
            "academic_revision": target.get_json()["academic_revision"],
            "name": "Revision writer", "course": "Course two", "semester": "Two",
            "college": "Example College", "age": 26, "daily_study_hours": 3,
        })
        self.assertEqual(profile_saved.status_code, 200, profile_saved.get_json())
        self.assertEqual(profile_saved.get_json()["academic_revision"], current_revision + 2)
        stale_collection = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": current_revision,
            "academic_profile": {"student_name": "Overwrite", "course": "Overwrite"},
            "subjects": [{"id": "revision-subject", "name": "Revision subject", "target_grade": "B"}],
            "classes": [],
        })
        self.assertEqual(stale_collection.status_code, 409, stale_collection.get_json())
        self.assertEqual(
            self.db.fetchone("SELECT target_grade FROM subjects WHERE id=%s AND user_id=%s", ("revision-subject", user["id"]))["target_grade"],
            "A",
        )

    def test_cross_student_grade_subject_and_task_delete_are_denied(self):
        owner_b = self.users["student_b"]["id"]
        subject = self.db.save_user_academic_state(
            owner_b, {"student_name": "Student B"}, [{"id": "subject-b", "name": "B subject"}], [], []
        )["subjects"][0]
        task_id = self.db.add_task(owner_b, {"id": "task-b", "title": "B task"})

        grade_response = self.client.post("/api/grades/add", headers=self.auth("student_a"), json={
            "subject_id": subject["id"], "assessment_name": "Attempted cross-account grade",
            "score": 9, "max_score": 10,
        })
        delete_response = self.client.post("/api/tasks/delete", headers=self.auth("student_a"), json={"task_id": task_id})
        self.assertEqual(grade_response.status_code, 404)
        self.assertEqual(delete_response.status_code, 404)
        self.assertEqual(self.db.get_user_grades(self.users["student_a"]["id"]), [])
        self.assertIsNotNone(self.db.fetchone(
            "SELECT id FROM tasks WHERE id = %s AND user_id = %s", (task_id, owner_b)
        ))

    def test_cross_student_exam_and_goal_deletes_are_denied(self):
        owner_b = self.users["student_b"]["id"]
        exam_id = self.db.add_exam(owner_b, {"id": "exam-b", "title": "B exam"})
        goal_id = self.db.add_goal(owner_b, {"id": "goal-b", "title": "B goal"})
        exam_response = self.client.post(
            "/api/exams/delete", headers=self.auth("student_a"), json={"exam_id": exam_id}
        )
        goal_response = self.client.post(
            "/api/goals/delete", headers=self.auth("student_a"), json={"goal_id": goal_id}
        )
        self.assertEqual(exam_response.status_code, 404)
        self.assertEqual(goal_response.status_code, 404)
        self.assertIsNotNone(self.db.fetchone(
            "SELECT id FROM exams WHERE id = %s AND user_id = %s", (exam_id, owner_b)
        ))
        self.assertIsNotNone(self.db.fetchone(
            "SELECT id FROM goals WHERE id = %s AND user_id = %s", (goal_id, owner_b)
        ))

    def test_academic_resave_preserves_existing_student_tasks(self):
        user, error = self.db.create_user(
            f"resave-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Resave student", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        original = self.db.add_task(user["id"], {"id": "keep-this-task", "title": "Student's saved task"})
        academic_revision, _calendar_revision = self.current_revisions(auth)
        response = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": academic_revision,
            "academic_profile": {"student_name": "Updated name", "course": "Updated course"},
            "subjects": [{"id": "new-subject", "name": "New subject"}], "classes": [],
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        current = self.db.get_user_tasks(user["id"])
        self.assertEqual([task["id"] for task in current], [original])
        self.assertEqual([task["id"] for task in response.get_json()["tasks"]], [original])

    def test_stale_academic_save_is_rejected_without_overwriting_newer_profile_subjects_or_classes(self):
        user, error = self.db.create_user(
            f"stale-academic-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Academic writer", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        old_revision, old_calendar_revision = self.current_revisions(auth)
        newest = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": old_revision,
            "academic_profile": {"student_name": "Newest", "course": "Current course"},
            "subjects": [{"id": "newest-subject", "name": "Current subject"}],
            "classes": [{"id": "newest-class", "subject": "Current subject", "day": "Friday"}],
        })
        self.assertEqual(newest.status_code, 200, newest.get_json())
        calendar_update = self.client.post("/api/academic/calendar-save", headers=auth, json={
            "calendar_revision": old_calendar_revision,
            "calendar_events": [{"id": "advanced-calendar", "title": "New calendar data"}],
            "calendar_exams": [],
        })
        self.assertEqual(calendar_update.status_code, 200, calendar_update.get_json())
        partial_stale = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": newest.get_json()["academic_revision"],
            "calendar_revision": old_calendar_revision,
            "academic_profile": {"student_name": "Must not partially save", "course": "Partial update"},
            "subjects": [{"id": "partial-subject", "name": "Partial subject"}],
            "classes": [], "calendar_events": [], "calendar_exams": [],
        })
        self.assertEqual(partial_stale.status_code, 409, partial_stale.get_json())
        self.assertEqual(self.db.get_user_academic_state(user["id"])["academic_profile"]["course"], "Current course")
        stale = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": old_revision,
            "academic_profile": {"student_name": "Stale", "course": "Old course"},
            "subjects": [{"id": "stale-subject", "name": "Old subject"}],
            "classes": [],
        })
        self.assertEqual(stale.status_code, 409, stale.get_json())
        self.assertEqual(stale.get_json()["code"], "stale_revision")
        current = self.db.get_user_academic_state(user["id"])
        self.assertEqual(current["academic_profile"]["course"], "Current course")
        self.assertEqual([row["name"] for row in current["subjects"]], ["Current subject"])
        self.assertEqual([row["id"] for row in current["classes"]], ["newest-class"])

    def test_stale_calendar_save_is_rejected_and_current_revision_succeeds(self):
        user, error = self.db.create_user(
            f"stale-calendar-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Calendar writer", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        _academic_revision, old_calendar_revision = self.current_revisions(auth)
        first = self.client.post("/api/academic/calendar-save", headers=auth, json={
            "calendar_revision": old_calendar_revision,
            "calendar_events": [{"id": "current-event", "title": "Current event", "date": "2026-11-01"}],
            "calendar_exams": [],
        })
        self.assertEqual(first.status_code, 200, first.get_json())
        stale = self.client.post("/api/academic/calendar-save", headers=auth, json={
            "calendar_revision": old_calendar_revision,
            "calendar_events": [{"id": "stale-event", "title": "Old event", "date": "2026-10-01"}],
            "calendar_exams": [],
        })
        self.assertEqual(stale.status_code, 409, stale.get_json())
        current = self.db.get_user_calendar(user["id"])
        self.assertEqual([item["id"] for item in current["calendar_events"]], ["current-event"])
        latest_revision = self.db.get_user_data_versions(user["id"])["calendar_revision"]
        normal = self.client.post("/api/academic/calendar-save", headers=auth, json={
            "calendar_revision": latest_revision,
            "calendar_events": [{"id": "updated-event", "title": "Updated event", "date": "2026-12-01"}],
            "calendar_exams": [],
        })
        self.assertEqual(normal.status_code, 200, normal.get_json())
        self.assertEqual([item["id"] for item in self.db.get_user_calendar(user["id"])["calendar_events"]], ["updated-event"])

    def test_saved_empty_calendar_stays_empty_if_compatibility_mirror_write_fails(self):
        user, error = self.db.create_user(
            f"empty-calendar-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Calendar owner", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        compatibility_state = self.server.load_db()
        compatibility_state.setdefault("registered_users", {})[user["email"]] = {
            "email": user["email"],
            "calendar_events": [{"id": "legacy-event", "title": "Legacy event"}],
            "calendar_exams": [{"id": "legacy-exam", "title": "Legacy exam"}],
        }
        self.server.save_db(compatibility_state)
        _academic_revision, calendar_revision = self.current_revisions(auth)
        before = self.client.get("/api/state", headers=auth).get_json()
        self.assertEqual(before["calendar_events"][0]["id"], "legacy-event")
        with patch.object(self.server, "save_db", side_effect=RuntimeError("simulated compatibility mirror failure")):
            response = self.client.post("/api/academic/calendar-save", headers=auth, json={
                "calendar_revision": calendar_revision,
                "calendar_events": [], "calendar_exams": [],
            })
        self.assertEqual(response.status_code, 200, response.get_json())
        after = self.client.get("/api/state", headers=auth).get_json()
        self.assertEqual(after["calendar_events"], [])
        self.assertEqual(after["calendar_exams"], [])

    def test_concurrent_first_academic_saves_only_allow_one_writer(self):
        user, error = self.db.create_user(
            f"first-save-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "First writer", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        initial_revision, _calendar_revision = self.current_revisions(auth)

        def save(subject_name):
            with self.server.app.test_client() as isolated_client:
                response = isolated_client.post("/api/academic/save", headers=auth, json={
                    "academic_revision": initial_revision,
                    "academic_profile": {"student_name": "First writer", "course": subject_name},
                    "subjects": [{"id": f"first-{subject_name}", "name": subject_name}],
                    "classes": [],
                })
                return response.status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = sorted(pool.map(save, ("Concurrent A", "Concurrent B")))
        self.assertEqual(statuses, [200, 409])
        current = self.db.get_user_academic_state(user["id"])
        self.assertEqual(len(current["subjects"]), 1)
        self.assertIn(current["subjects"][0]["name"], ("Concurrent A", "Concurrent B"))

    def test_academic_save_imports_compatibility_tasks_when_normalized_collection_is_empty(self):
        user, error = self.db.create_user(
            f"compat-tasks-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Legacy task owner", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        self.client.get("/api/state", headers=auth)
        state = self.server.load_db()
        root_task = {
            "id": "root-only-task", "subject": "Legacy Biology", "title": "Root-only work",
            "status": "In Progress", "verified": False, "points_reward": 40,
        }
        root_duplicate = {
            "id": "shared-legacy-task", "subject": "Legacy Biology", "title": "Existing work",
            "status": "Completed", "verified": True, "verified_file": "proof.pdf",
            "verified_at": "2026-01-02T03:04:05", "proof_required": "show work",
            "quiz_score": "8/10", "points": 80, "points_reward": 75,
        }
        nested_duplicate = {
            "id": "shared-legacy-task", "subject": "Legacy Biology", "title": "Existing work",
            "status": "Pending", "verified": False, "verified_file": "", "quiz_score": "",
            "points": 20, "points_reward": 25,
        }
        nested_task = {
            "id": "nested-only-task", "subject": "Legacy Biology", "title": "Nested-only work",
            "status": "Pending", "verified": False, "points_reward": 30,
        }
        state["tasks"] = [root_task, root_duplicate]
        state.setdefault("registered_users", {}).setdefault(user["email"], {})["tasks"] = [nested_duplicate, nested_task]
        self.server.save_db(state)
        academic_revision, _calendar_revision = self.current_revisions(auth)
        saved = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": academic_revision,
            "academic_profile": {"student_name": "Legacy task owner", "course": "Biology"},
            "subjects": [{"id": "biology", "name": "Biology"}], "classes": [],
        })
        self.assertEqual(saved.status_code, 200, saved.get_json())
        tasks = self.db.get_user_tasks(user["id"])
        self.assertEqual({task["id"] for task in tasks}, {"root-only-task", "shared-legacy-task", "nested-only-task"})
        self.assertEqual(len(tasks), 3)
        by_id = {task["id"]: task for task in tasks}
        self.assertEqual(by_id["shared-legacy-task"]["status"], "Completed")
        self.assertEqual(by_id["shared-legacy-task"]["verified"], 1)
        self.assertEqual(by_id["shared-legacy-task"]["verified_file"], "proof.pdf")
        self.assertEqual(by_id["shared-legacy-task"]["verified_at"], "2026-01-02T03:04:05")
        self.assertEqual(by_id["shared-legacy-task"]["quiz_score"], "8/10")
        self.assertEqual(by_id["shared-legacy-task"]["description"], "show work")
        self.assertEqual(by_id["shared-legacy-task"]["points_reward"], 75)
        self.assertTrue(all(task["user_id"] == user["id"] for task in tasks))

    def test_academic_save_does_not_replace_existing_normalized_tasks_with_compatibility_snapshot(self):
        user, error = self.db.create_user(
            f"normalized-task-wins-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Task owner", role="student"
        )
        self.assertIsNone(error)
        self.db.add_task(user["id"], {
            "id": "normalized-current", "subject": "Math", "title": "Current task",
            "status": "Completed", "verified": True,
        })
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        self.client.get("/api/state", headers=auth)
        state = self.server.load_db()
        state.setdefault("registered_users", {}).setdefault(user["email"], {})["tasks"] = [{
            "id": "compatibility-stale", "title": "Stale task", "status": "Pending",
        }]
        state["tasks"] = [{"id": "root-stale", "title": "Root stale task"}]
        self.server.save_db(state)
        academic_revision, _calendar_revision = self.current_revisions(auth)
        response = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": academic_revision,
            "academic_profile": {"student_name": "Task owner", "course": "Math"},
            "subjects": [{"id": "math", "name": "Math"}], "classes": [],
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        rows = self.db.get_user_tasks(user["id"])
        self.assertEqual([row["id"] for row in rows], ["normalized-current"])
        self.assertEqual(rows[0]["status"], "Completed")
        self.assertEqual(rows[0]["verified"], 1)

    def test_concurrent_task_creation_survives_academic_save(self):
        user, error = self.db.create_user(
            f"task-academic-race-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Concurrent owner", role="student"
        )
        self.assertIsNone(error)
        revision = self.db.get_user_data_versions(user["id"])["academic_revision"]
        academic_locked = threading.Event()
        task_started = threading.Event()
        release_academic = threading.Event()
        task_lock_calls = []
        worker = threading.local()
        original_lock = self.db._lock_task_owner

        def controlled_lock(cursor, user_id):
            task_lock_calls.append(getattr(worker, "kind", None))
            result = original_lock(cursor, user_id)
            if getattr(worker, "kind", None) == "academic":
                academic_locked.set()
                self.assertTrue(release_academic.wait(5), "test did not release the academic save")
            return result

        def save_academic():
            worker.kind = "academic"
            return self.db.save_user_academic_state(
                user["id"], {"student_name": "Concurrent owner", "course": "Physics"},
                [{"id": "physics", "name": "Physics"}], [], [], preserve_existing_tasks=True,
                expected_revision=revision,
            )

        def create_task():
            worker.kind = "task"
            task_started.set()
            return self.db.add_task(user["id"], {
                "id": "concurrent-task", "subject": "Physics", "title": "Do not lose me",
                "status": "In Progress", "verified": True,
            })

        with patch.object(self.db, "_lock_task_owner", side_effect=controlled_lock):
            with ThreadPoolExecutor(max_workers=2) as pool:
                save_future = pool.submit(save_academic)
                self.assertTrue(academic_locked.wait(5), "academic transaction did not take the shared owner lock")
                task_future = pool.submit(create_task)
                self.assertTrue(task_started.wait(5), "task creation did not begin while save held the lock")
                release_academic.set()
                save_future.result(timeout=10)
                task_id = task_future.result(timeout=10)
        self.assertCountEqual(task_lock_calls, ["academic", "task"])
        self.assertEqual(task_id, "concurrent-task")
        rows = self.db.get_user_tasks(user["id"])
        self.assertEqual([row["id"] for row in rows], ["concurrent-task"])
        self.assertEqual(rows[0]["status"], "In Progress")

    def test_state_retries_if_collections_change_during_snapshot_read(self):
        user, error = self.db.create_user(
            f"snapshot-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Snapshot", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        self.db.save_user_academic_state(user["id"], {"student_name": "Snapshot", "course": "Old"}, [], [], [])
        original_read = self.db.get_user_academic_state
        reads = {"count": 0}

        def race_read(user_id):
            state = original_read(user_id)
            if reads["count"] == 0:
                reads["count"] += 1
                revision = self.db.get_user_data_versions(user_id)["academic_revision"]
                self.db.save_user_academic_state(
                    user_id, {"student_name": "Snapshot", "course": "New"}, [], [], [],
                    expected_revision=revision,
                )
            return state

        with patch.object(self.db, "get_user_academic_state", side_effect=race_read):
            response = self.client.get("/api/state", headers=auth)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["academic_profile"]["course"], "New")
        self.assertEqual(response.get_json()["academic_revision"], 2)

    def test_save_response_keeps_its_committed_revision_if_a_later_writer_commits(self):
        user, error = self.db.create_user(
            f"response-revision-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Revision response", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        initial_revision, _calendar_revision = self.current_revisions(auth)

        def later_writer(_state):
            self.db.save_user_academic_state(
                user["id"], {"student_name": "Revision response", "course": "Later writer"}, [], [], [],
                expected_revision=2,
            )

        with patch.object(self.server, "save_db", side_effect=later_writer):
            response = self.client.post("/api/academic/save", headers=auth, json={
                "academic_revision": initial_revision,
                "academic_profile": {"student_name": "Revision response", "course": "First writer"},
                "subjects": [], "classes": [],
            })
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["academic_revision"], 2)
        self.assertEqual(self.db.get_user_data_versions(user["id"])["academic_revision"], 3)
        stale = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": response.get_json()["academic_revision"],
            "academic_profile": {"student_name": "Revision response", "course": "Stale retry"},
            "subjects": [], "classes": [],
        })
        self.assertEqual(stale.status_code, 409, stale.get_json())

    def test_version_rows_use_engine_appropriate_locking_sql(self):
        class Cursor:
            def __init__(self):
                self.calls = []

            def execute(self, query, params):
                self.calls.append((query, params))

            def fetchone(self):
                return {"academic_version": 1, "calendar_version": 1}

        manager = type(self.db).__new__(type(self.db))
        manager._translate_query = lambda query: query
        for engine, has_row_lock in (("mysql", True), ("sqlite", False)):
            manager.engine_type = engine
            cursor = Cursor()
            manager._lock_user_data_versions(cursor, "scoped-user", "academic_version", 1)
            select_sql = cursor.calls[1][0]
            self.assertEqual("FOR UPDATE" in select_sql, has_row_lock)
            self.assertEqual(cursor.calls[0][1], ("scoped-user",))

    def test_failed_combined_save_rolls_back_collections_and_revisions(self):
        user, error = self.db.create_user(
            f"rollback-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Rollback", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        auth = {"Authorization": f"Bearer {token}"}
        academic_revision, calendar_revision = self.current_revisions(auth)
        before = self.db.get_user_academic_state(user["id"])
        response = self.client.post("/api/academic/save", headers=auth, json={
            "academic_revision": academic_revision,
            "calendar_revision": calendar_revision,
            "academic_profile": {"student_name": "Should roll back", "course": "Uncommitted"},
            "subjects": [{"id": "rollback-subject", "name": "Uncommitted subject"}],
            "classes": [], "calendar_events": ["not-an-object"], "calendar_exams": [],
        })
        self.assertEqual(response.status_code, 400, response.get_json())
        current = self.db.get_user_academic_state(user["id"])
        self.assertEqual(current["subjects"], before["subjects"])
        self.assertEqual(current["academic_profile"], before["academic_profile"])
        self.assertEqual(self.db.get_user_data_versions(user["id"]), {
            "academic_revision": academic_revision,
            "calendar_revision": calendar_revision,
        })

    def test_generate_tasks_preserves_existing_progress_and_adds_only_missing_suggestions(self):
        user, error = self.db.create_user(
            f"generate-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Generator", role="student"
        )
        self.assertIsNone(error)
        token = self.db.create_session(user["id"])
        self.db.save_user_academic_state(user["id"], {"student_name": "Generator"}, [
            {"id": "generate-subject", "name": "Biology"},
        ], [], [])
        existing = self.db.add_task(user["id"], {
            "id": "completed-biology", "subject": "Biology",
            "title": "Complete Biology Problem Set & Module Review", "status": "Completed", "verified": True,
        })
        response = self.client.post(
            "/api/tasks/generate", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        rows = self.db.get_user_tasks(user["id"])
        retained = next(task for task in rows if task["id"] == existing)
        self.assertEqual(retained["status"], "Completed")
        self.assertEqual(retained["verified"], 1)
        self.assertEqual(sum(task["title"] == "Complete Biology Problem Set & Module Review" for task in rows), 1)

    def test_parent_dashboard_obeys_each_disabled_student_permission(self):
        student = self.users["student_a"]
        parent = self.users["parent"]
        self.db.save_user_academic_state(student["id"], {"student_name": "Student A"}, [], [], [
            {"id": "private-task", "title": "Private task", "status": "Pending", "due_date": "2099-01-01"}
        ])
        self.db.add_exam(student["id"], {"id": "private-exam", "title": "Private exam", "exam_date": "2099-02-01"})
        self.db.add_study_session(student["id"], {"id": "private-session", "duration_minutes": 120, "date": datetime.date.today().isoformat()})
        link_id, error = self.db.link_parent_student(parent["email"], student["email"], "Parent")
        self.assertIsNone(error)
        self.assertTrue(self.db.approve_parent_link(link_id, student["id"]))
        denied = {
            "tasks": False, "consistency": False, "study_time": False,
            "login_activity": False, "exam_information": False,
            "study_history": False, "digital_twin_insights": False,
        }
        self.db.initialize_application_state({
            "parent_permissions": {student["email"]: denied}
        }, state_key="user:" + str(student["id"]))

        response = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"],
            headers=self.auth("parent"),
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertIsNone(payload["overview"]["current_streak"])
        self.assertIsNone(payload["overview"]["weekly_study_time"])
        self.assertIsNone(payload["overview"]["tasks_completed_ratio"])
        self.assertIsNone(payload["overview"]["upcoming_exam_days"])
        self.assertIsNone(payload["task_progress"]["total"])
        self.assertIsNone(payload["weekly_study_time"]["total_this_week"])
        self.assertIsNone(payload["consistency"]["days_studied_this_week"])
        self.assertEqual(payload["task_progress"]["items"], [])
        self.assertEqual(payload["upcoming_exams"]["exams"], [])

        mixed = {**denied, "consistency": True, "digital_twin_insights": True}
        state, version = self.db.load_application_state("user:" + str(student["id"]))
        state["parent_permissions"][student["email"]] = mixed
        version = self.db.save_application_state(state, version, state_key="user:" + str(student["id"]))
        consistency_only = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"],
            headers=self.auth("parent"),
        ).get_json()
        self.assertTrue(consistency_only["consistency"]["permitted"])
        self.assertTrue(any(row["studied"] for row in consistency_only["consistency"]["heatmap"]))
        self.assertTrue(all("hours" not in row for row in consistency_only["consistency"]["heatmap"]))
        insight_text = " ".join(item["text"] for item in consistency_only["ai_insights"]["insights"])
        self.assertNotIn("study session", insight_text)
        self.assertNotIn("private-session", __import__("json").dumps(consistency_only))
        self.assertNotIn("task(s)", insight_text)
        self.assertNotIn("exam(s)", insight_text)

        with_study_time = {**mixed, "study_time": True}
        state["parent_permissions"][student["email"]] = with_study_time
        self.db.save_application_state(state, version, state_key="user:" + str(student["id"]))
        permitted = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"],
            headers=self.auth("parent"),
        ).get_json()
        self.assertIsNotNone(permitted["weekly_study_time"]["total_this_week"])
        self.assertTrue(any("study session" in item["text"] for item in permitted["ai_insights"]["insights"]))

    def test_parent_link_requires_student_approval_and_revocation_removes_access(self):
        student, error = self.db.create_user(
            f"link-student-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Link student", role="student"
        )
        self.assertIsNone(error)
        parent, error = self.db.create_user(
            f"link-parent-{uuid.uuid4().hex}@example.test", "Disposable-Password-42!", "Link parent", role="parent"
        )
        self.assertIsNone(error)
        student_token = self.db.create_session(student["id"])
        parent_token = self.db.create_session(parent["id"])
        student_auth = {"Authorization": f"Bearer {student_token}"}
        parent_auth = {"Authorization": f"Bearer {parent_token}"}

        requested = self.client.post("/api/parent/link-student", headers=parent_auth, json={
            "student_email": student["email"],
        })
        self.assertEqual(requested.status_code, 200, requested.get_json())
        pending_view = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"], headers=parent_auth
        )
        self.assertEqual(pending_view.status_code, 403)
        relationship_id = requested.get_json()["relationship"]["id"]

        approved = self.client.post("/api/student/approve-parent", headers=student_auth, json={
            "relationship_id": relationship_id,
        })
        self.assertEqual(approved.status_code, 200, approved.get_json())
        allowed_view = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"], headers=parent_auth
        )
        self.assertEqual(allowed_view.status_code, 200, allowed_view.get_json())

        revoked = self.client.post("/api/student/revoke-parent", headers=student_auth, json={
            "relationship_id": relationship_id,
        })
        self.assertEqual(revoked.status_code, 200, revoked.get_json())
        blocked_view = self.client.get(
            "/api/parent/dashboard-data?student_email=" + student["email"], headers=parent_auth
        )
        self.assertEqual(blocked_view.status_code, 403)


if __name__ == "__main__":
    unittest.main()
