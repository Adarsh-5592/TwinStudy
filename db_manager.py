"""
TwinStudy AI - Authoritative Relational Database Manager
Production-grade persistence supporting Managed Remote MySQL (with SSL) and local SQLite fallback.
Provides user-scoped academic data isolation, session security, parent governance,
and eliminates reliance on temporary Vercel filesystem storage.
"""

import os
import json
import uuid
import datetime
import urllib.parse
import sqlite3
import secrets
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash


class ConcurrentUpdateError(RuntimeError):
    """A submitted academic collection was based on an older saved revision."""

# -----------------------------------------------------------------------------
# Configuration from Environment
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_URL") or ""

if DATABASE_URL:
    try:
        parsed_url = urllib.parse.urlparse(DATABASE_URL)
        MYSQL_USER = urllib.parse.unquote(parsed_url.username or "root")
        MYSQL_PASSWORD = urllib.parse.unquote(parsed_url.password or "")
        MYSQL_HOST = parsed_url.hostname or "127.0.0.1"
        MYSQL_PORT = parsed_url.port or 3306
        MYSQL_DATABASE = parsed_url.path.lstrip("/").split("?")[0] or "twinstudy"
    except Exception as e:
        print(f"[DB CONFIG WARNING] Could not parse DATABASE_URL: {e}. Falling back to individual env vars.")
        MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
        MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
        MYSQL_USER = os.environ.get("MYSQL_USER", "root")
        MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
        MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "twinstudy")
else:
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
    MYSQL_USER = os.environ.get("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "twinstudy")

MYSQL_SSL_MODE = os.environ.get("MYSQL_SSL_MODE", "").strip().upper()
MYSQL_SSL_CA = os.environ.get("MYSQL_SSL_CA", "").strip()
MYSQL_SSL_ENABLED = os.environ.get("MYSQL_SSL", "").lower() in ("true", "1", "yes") or bool(MYSQL_SSL_CA) or MYSQL_SSL_MODE in ("REQUIRED", "PREFERRED")

IS_VERCEL = bool(os.environ.get("VERCEL"))
if IS_VERCEL:
    SQLITE_PATH = "/tmp/twin_relational.db"
    LEGACY_JSON_PATH = "/tmp/twin_database.json"
    bundled_sqlite = os.path.join(os.path.dirname(__file__), "twin_relational.db")
    bundled_json = os.path.join(os.path.dirname(__file__), "twin_database.json")
    import shutil
    if not os.path.exists(SQLITE_PATH) and os.path.exists(bundled_sqlite):
        try:
            shutil.copyfile(bundled_sqlite, SQLITE_PATH)
        except Exception:
            pass
    if not os.path.exists(LEGACY_JSON_PATH) and os.path.exists(bundled_json):
        try:
            shutil.copyfile(bundled_json, LEGACY_JSON_PATH)
        except Exception:
            pass
else:
    SQLITE_PATH = os.path.join(os.path.dirname(__file__), "twin_relational.db")
    LEGACY_JSON_PATH = os.path.join(os.path.dirname(__file__), "twin_database.json")


def safe_int(val, default=0):
    try:
        if val is None or val == "":
            return default
        return int(val)
    except Exception:
        return default


def safe_float(val, default=0.0):
    try:
        if val is None or val == "":
            return default
        return float(val)
    except Exception:
        return default


class DatabaseManager:
    def __init__(self):
        self.engine_type = "sqlite"
        self._test_mysql_and_init()

    def _get_mysql_ssl_config(self):
        if not MYSQL_SSL_ENABLED:
            return None
        ssl_cfg = {}
        if MYSQL_SSL_CA and os.path.exists(MYSQL_SSL_CA):
            ssl_cfg["ca"] = MYSQL_SSL_CA
        else:
            # Prefer or require SSL if server supports it
            ssl_cfg["ssl_mode"] = "PREFERRED"
        return ssl_cfg

    def _test_mysql_and_init(self):
        # Only attempt MySQL if configured with non-default host or explicit password or non-local host
        has_explicit_mysql = bool(
            os.environ.get("DATABASE_URL")
            or os.environ.get("MYSQL_URL")
            or os.environ.get("MYSQL_PASSWORD")
            or os.environ.get("MYSQL_HOST")
        )

        is_production = bool(
            os.environ.get("VERCEL")
            or os.environ.get("IS_VERCEL")
            or os.environ.get("ENVIRONMENT", "").lower() == "production"
            or os.environ.get("NODE_ENV", "").lower() == "production"
            or os.environ.get("FLASK_ENV", "").lower() == "production"
        )
        allow_sqlite_fallback = os.environ.get("ALLOW_SQLITE_FALLBACK", "").strip().lower() in ("1", "true", "yes")

        # Production must never silently accept ephemeral SQLite, even if a fallback
        # flag was accidentally copied into the hosting environment.
        if is_production and not has_explicit_mysql:
            raise RuntimeError(
                "CRITICAL: Production environment detected (Vercel/Production) but no MySQL credentials were provided. "
                "Managed remote MySQL is required to eliminate ephemeral filesystem data loss. "
                "Configure DATABASE_URL or MYSQL_* environment variables, or set ALLOW_SQLITE_FALLBACK=true for testing."
            )

        
        ssl_config = self._get_mysql_ssl_config()

        try:
            conn_kwargs = {
                "host": MYSQL_HOST,
                "port": MYSQL_PORT,
                "user": MYSQL_USER,
                "password": MYSQL_PASSWORD,
                "database": MYSQL_DATABASE,
                "connect_timeout": 4,
                "charset": "utf8mb4"
            }
            if ssl_config:
                conn_kwargs["ssl"] = ssl_config

            conn = pymysql.connect(**conn_kwargs)
            conn.close()
            self.engine_type = "mysql"
            print(
                f"[DB] Successfully connected to MariaDB at "
                f"{MYSQL_HOST}:{MYSQL_PORT}, database: {MYSQL_DATABASE}"
            )
        except Exception as e:
            if has_explicit_mysql and (is_production or not allow_sqlite_fallback):
                raise RuntimeError(
                    "MySQL/MariaDB connection failed. SQLite fallback is disabled for this environment. "
                    "Check your database configuration and credentials."
                ) from e

            if is_production:
                raise RuntimeError(
                    "Production requires a working MySQL/MariaDB connection. "
                    "SQLite fallback is never permitted in production."
                ) from e

            self.engine_type = "sqlite"
            print(
                f"[DB WARNING] Using SQLite at {SQLITE_PATH}. "
                "MySQL was not selected or SQLite fallback was explicitly allowed."
            )


        self.init_schema()
        # Migration disabled until explicitly approved.
        # self.migrate_from_json_if_needed()

    def get_connection(self):
        if self.engine_type == "mysql":
            ssl_config = self._get_mysql_ssl_config()
            conn_kwargs = {
                "host": MYSQL_HOST,
                "port": MYSQL_PORT,
                "user": MYSQL_USER,
                "password": MYSQL_PASSWORD,
                "database": MYSQL_DATABASE,
                "cursorclass": DictCursor,
                "autocommit": True,
                "charset": "utf8mb4",
                "connect_timeout": 5
            }
            if ssl_config:
                conn_kwargs["ssl"] = ssl_config
            return pymysql.connect(**conn_kwargs)
        else:
            conn = sqlite3.connect(SQLITE_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn

    def _translate_query(self, query: str) -> str:
        if self.engine_type == "sqlite":
            q = query.replace("%s", "?")
            q = q.replace("INSERT IGNORE INTO", "INSERT OR IGNORE INTO")
            return q
        else:
            q = query.replace("INSERT OR IGNORE INTO", "INSERT IGNORE INTO")
            return q

    def execute(self, query: str, params=()):
        conn = self.get_connection()
        try:
            sql = self._translate_query(query)
            cur = conn.cursor()
            cur.execute(sql, params)
            if self.engine_type == "sqlite":
                conn.commit()
            return cur
        finally:
            conn.close()

    def fetchone(self, query: str, params=()):
        conn = self.get_connection()
        try:
            sql = self._translate_query(query)
            cur = conn.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()
            if self.engine_type == "sqlite":
                return dict(row) if row else None
            return row
        finally:
            conn.close()

    def fetchall(self, query: str, params=()):
        conn = self.get_connection()
        try:
            sql = self._translate_query(query)
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            if self.engine_type == "sqlite":
                return [dict(r) for r in rows]
            return list(rows) if rows else []
        finally:
            conn.close()

    def init_schema(self):
        """Creates all 20 tables with relational integrity and dialect compatibility."""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(64) PRIMARY KEY,
                email VARCHAR(191) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(191),
                role VARCHAR(32) DEFAULT 'student',
                dob VARCHAR(32),
                age INT DEFAULT 20,
                is_minor INT DEFAULT 0,
                points INT DEFAULT 100,
                streak_days INT DEFAULT 1,
                daily_study_hours REAL DEFAULT 3.0,
                focus_duration_minutes INT DEFAULT 45,
                learning_preference TEXT,
                preferred_study_time VARCHAR(64) DEFAULT 'Evening',
                college VARCHAR(191),
                grade_level VARCHAR(191),
                guardian_email VARCHAR(191),
                linking_code VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS student_profiles (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                student_name VARCHAR(191),
                college VARCHAR(191),
                course VARCHAR(191),
                semester VARCHAR(64),
                specialization VARCHAR(64) DEFAULT 'cs',
                academic_year VARCHAR(64) DEFAULT '2026-2027',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS subjects (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                name VARCHAR(191) NOT NULL,
                code VARCHAR(64),
                credits INT DEFAULT 3,
                target_percentage REAL DEFAULT 85.0,
                target_grade VARCHAR(16) DEFAULT 'A',
                professor VARCHAR(191),
                teacher VARCHAR(191),
                room VARCHAR(64),
                color VARCHAR(32) DEFAULT '#3b82f6',
                type VARCHAR(64) DEFAULT 'Lecture',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS classes (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                subject_id VARCHAR(64),
                subject_name VARCHAR(191),
                subject VARCHAR(191),
                day VARCHAR(32) NOT NULL,
                time_slot VARCHAR(64) NOT NULL,
                time VARCHAR(64),
                start_time VARCHAR(32),
                end_time VARCHAR(32),
                room VARCHAR(64),
                professor VARCHAR(191),
                teacher VARCHAR(191),
                color VARCHAR(32) DEFAULT '#3b82f6',
                type VARCHAR(64) DEFAULT 'Lecture',
                week_type VARCHAR(64) DEFAULT 'All',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                subject_id VARCHAR(64),
                subject_name VARCHAR(191),
                title VARCHAR(255) NOT NULL,
                description TEXT,
                due_date VARCHAR(64),
                priority VARCHAR(32) DEFAULT 'medium',
                status VARCHAR(64) DEFAULT 'Pending',
                points_reward INT DEFAULT 100,
                verified INT DEFAULT 0,
                verified_file VARCHAR(255),
                quiz_score VARCHAR(32),
                verified_at VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS exams (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                subject_id VARCHAR(64),
                subject_name VARCHAR(191),
                title VARCHAR(255) NOT NULL,
                exam_date VARCHAR(64),
                weight_pct REAL DEFAULT 30.0,
                target_score REAL DEFAULT 85.0,
                syllabus_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS grades (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                subject_id VARCHAR(64),
                subject_name VARCHAR(191),
                assessment_type VARCHAR(64),
                title VARCHAR(255),
                marks_obtained REAL,
                max_marks REAL,
                percentage REAL,
                grade VARCHAR(16),
                term VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS study_sessions (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                subject_name VARCHAR(191),
                duration_minutes INT,
                focus_score REAL,
                stamina_start REAL,
                stamina_end REAL,
                date VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS goals (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                title VARCHAR(255),
                category VARCHAR(64),
                target_date VARCHAR(64),
                status VARCHAR(64) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS behavior_patterns (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                title VARCHAR(255),
                pattern_type VARCHAR(64),
                confidence REAL DEFAULT 85.0,
                evidence_count INT DEFAULT 1,
                evidence_summary TEXT,
                weight REAL DEFAULT 1.0,
                is_active INT DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                question TEXT,
                baseline_data TEXT,
                simulation_result TEXT,
                recommended_option VARCHAR(191),
                chosen_option VARCHAR(191),
                agreement VARCHAR(32),
                user_reason TEXT,
                outcome_rating INT,
                outcome_feedback TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                decision_id VARCHAR(64),
                feedback_type VARCHAR(64),
                comments TEXT,
                rating INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS permissions (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                guardian_email VARCHAR(191),
                allow_view_study_hours INT DEFAULT 1,
                allow_view_proofs INT DEFAULT 1,
                allow_nudges INT DEFAULT 1,
                approved INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS parent_student_links (
                id VARCHAR(64) PRIMARY KEY,
                parent_id VARCHAR(64),
                student_id VARCHAR(64),
                parent_email VARCHAR(191) NOT NULL,
                student_email VARCHAR(191) NOT NULL,
                parent_name VARCHAR(191),
                student_name VARCHAR(191),
                status VARCHAR(32) DEFAULT 'pending',
                linking_code VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_at VARCHAR(64)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS privacy_settings (
                user_id VARCHAR(64) PRIMARY KEY,
                academic_calendar INT DEFAULT 1,
                biometric_telemetry INT DEFAULT 1,
                parent_live_nudges INT DEFAULT 1,
                allow_research_benchmarking INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS academic_calendar_events (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                event_date VARCHAR(64),
                title VARCHAR(255),
                event_type VARCHAR(64),
                payload_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS academic_calendar_exams (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                exam_date VARCHAR(64),
                title VARCHAR(255),
                subject_name VARCHAR(191),
                payload_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS user_data_versions (
                user_id VARCHAR(64) PRIMARY KEY,
                academic_version BIGINT NOT NULL DEFAULT 1,
                calendar_version BIGINT NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS application_state (
                state_key VARCHAR(64) PRIMARY KEY,
                state_json LONGTEXT NOT NULL,
                version BIGINT NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS verification_otps (
                email VARCHAR(191) PRIMARY KEY,
                code VARCHAR(64) NOT NULL,
                purpose VARCHAR(64) NOT NULL,
                data TEXT,
                attempts_left INT DEFAULT 5,
                expires_at VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                title VARCHAR(255),
                description TEXT,
                type VARCHAR(64) DEFAULT 'info',
                is_read INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS chat_conversations (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                title VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id VARCHAR(64) PRIMARY KEY,
                conversation_id VARCHAR(64) NOT NULL,
                user_id VARCHAR(64) NOT NULL,
                role VARCHAR(32) NOT NULL,
                content TEXT NOT NULL,
                context_used TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(128) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
            """
        ]

        conn = self.get_connection()
        try:
            cur = conn.cursor()
            for stmt in tables:
                sql = self._translate_query(stmt)
                cur.execute(sql)
            if self.engine_type == "sqlite":
                conn.commit()
            print("[DB] Relational schema initialized successfully.")
        finally:
            conn.close()

        self._ensure_columns_exist()

    def _ensure_columns_exist(self):
        """Ensures that all optional and newly added columns exist without losing existing data."""
        try:
            if self.engine_type == "sqlite":
                conn = self.get_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("PRAGMA table_info(subjects)")
                    cur_cols = [r[1] for r in cur.fetchall()]
                    if "teacher" not in cur_cols:
                        cur.execute("ALTER TABLE subjects ADD COLUMN teacher VARCHAR(191)")
                    if "type" not in cur_cols:
                        cur.execute("ALTER TABLE subjects ADD COLUMN type VARCHAR(64) DEFAULT 'Lecture'")
                    if "target_grade" not in cur_cols:
                        cur.execute("ALTER TABLE subjects ADD COLUMN target_grade VARCHAR(16) DEFAULT 'A'")

                    cur.execute("PRAGMA table_info(classes)")
                    cls_cols = [r[1] for r in cur.fetchall()]
                    cols_to_add = [
                        ("subject", "VARCHAR(191)"),
                        ("time", "VARCHAR(64)"),
                        ("start_time", "VARCHAR(32)"),
                        ("end_time", "VARCHAR(32)"),
                        ("teacher", "VARCHAR(191)"),
                        ("type", "VARCHAR(64) DEFAULT 'Lecture'"),
                        ("week_type", "VARCHAR(64) DEFAULT 'All'")
                    ]
                    for col, ctype in cols_to_add:
                        if col not in cls_cols:
                            cur.execute(f"ALTER TABLE classes ADD COLUMN {col} {ctype}")

                    cur.execute("PRAGMA table_info(behavior_patterns)")
                    bp_cols = [r[1] for r in cur.fetchall()]
                    if "pattern_id" not in bp_cols:
                        cur.execute("ALTER TABLE behavior_patterns ADD COLUMN pattern_id VARCHAR(64)")

                    conn.commit()
                finally:
                    conn.close()
            else:
                for col, ctype in [
                    ("teacher", "VARCHAR(191)"),
                    ("type", "VARCHAR(64) DEFAULT 'Lecture'"),
                    ("target_grade", "VARCHAR(16) DEFAULT 'A'")
                ]:
                    try:
                        self.execute(f"ALTER TABLE subjects ADD COLUMN {col} {ctype}")
                    except Exception:
                        pass
                for col, ctype in [
                    ("subject", "VARCHAR(191)"),
                    ("time", "VARCHAR(64)"),
                    ("start_time", "VARCHAR(32)"),
                    ("end_time", "VARCHAR(32)"),
                    ("teacher", "VARCHAR(191)"),
                    ("type", "VARCHAR(64) DEFAULT 'Lecture'"),
                    ("week_type", "VARCHAR(64) DEFAULT 'All'")
                ]:
                    try:
                        self.execute(f"ALTER TABLE classes ADD COLUMN {col} {ctype}")
                    except Exception:
                        pass
                try:
                    self.execute("ALTER TABLE behavior_patterns ADD COLUMN pattern_id VARCHAR(64)")
                except Exception:
                    pass
                try:
                    self.execute("ALTER TABLE verification_otps MODIFY COLUMN code VARCHAR(64) NOT NULL")
                except Exception as exc:
                    # Some databases may already be at the current schema version.
                    print(f"[DB] OTP schema compatibility note: {type(exc).__name__}")
        except Exception as e:
            print(f"[DB] Notice during column migration: {e}")

    def migrate_from_json_if_needed(self):
        """Fail closed until a protected, validated migration runner exists."""
        raise RuntimeError(
            "Legacy JSON migration is disabled. Use a reviewed runner with a dry run, "
            "verified backup/restore, and duplicate-safe inserts against an isolated copy."
        )

    # -------------------------------------------------------------------------
    # USER & AUTHENTICATION METHODS
    # -------------------------------------------------------------------------
    def get_user_by_email(self, email: str):
        if not email:
            return None
        return self.fetchone("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email.strip(),))

    def get_user_by_id(self, user_id: str):
        if not user_id:
            return None
        return self.fetchone("SELECT * FROM users WHERE id = %s", (user_id,))

    def get_user_by_linking_code(self, code: str):
        if not code:
            return None
        return self.fetchone("SELECT * FROM users WHERE UPPER(linking_code) = UPPER(%s)", (code.strip(),))

    def create_user(self, email: str, password: str, name: str, role="student", **kwargs):
        email_clean = str(email or "").strip().lower()
        name_clean = str(name or "").strip()[:191]
        if not email_clean or len(email_clean) > 191 or "@" not in email_clean:
            return None, "Enter a valid email address."
        if role not in ("student", "parent", "guardian", "student_adult", "student_minor"):
            return None, "Unsupported account role."
        supplied_hash = kwargs.get("password_hash")
        password_hash = str(supplied_hash) if supplied_hash else generate_password_hash(password)
        if not (password_hash.startswith("scrypt:") or password_hash.startswith("pbkdf2:")):
            return None, "Invalid password credential format. Restart registration and try again."
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        age = safe_int(kwargs.get("age"), 20)
        dob = str(kwargs.get("dob", "") or "")[:32]
        is_minor = 1 if kwargs.get("is_minor") else (1 if age < 18 and str(role).startswith("student") else 0)
        guardian_email = str(kwargs.get("guardian_email") or "").strip().lower()[:191]
        linking_code = str(kwargs.get("linking_code") or f"TS-LINK-{random_digits(4)}")[:64]

        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
                return cur
            execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s) LIMIT 1", (email_clean,))
            if cur.fetchone():
                conn.rollback()
                return None, "An account with this email address already exists."
            execute("""INSERT INTO users
                (id,email,password_hash,name,role,dob,age,is_minor,guardian_email,linking_code)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (user_id, email_clean, password_hash, name_clean, role, dob, age, is_minor, guardian_email, linking_code))
            execute("INSERT INTO student_profiles (id,user_id,student_name) VALUES (%s,%s,%s)",
                    (f"prof_{user_id}", user_id, name_clean))
            execute("""INSERT INTO permissions
                (id,user_id,guardian_email,allow_view_study_hours,allow_view_proofs,allow_nudges,approved)
                VALUES (%s,%s,%s,1,1,1,0)""", (f"perm_{user_id}", user_id, guardian_email))
            execute("""INSERT INTO privacy_settings
                (user_id,academic_calendar,biometric_telemetry,parent_live_nudges,allow_research_benchmarking)
                VALUES (%s,1,1,1,0)""", (user_id,))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()
        return self.get_user_by_id(user_id), None

    def verify_user_login(self, identifier: str, password: str):
        user = self.get_user_by_email(identifier)
        if not user:
            user = self.get_user_by_linking_code(identifier)
        if not user:
            return None, "No account found with this email address."

        stored_hash = user.get("password_hash", "")
        if stored_hash.startswith("scrypt:") or stored_hash.startswith("pbkdf2:"):
            if not check_password_hash(stored_hash, password):
                return None, "Incorrect password. Please try again."
        else:
            if stored_hash != password:
                return None, "Incorrect password. Please try again."
            new_hash = generate_password_hash(password)
            self.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user["id"]))

        return user, None

    def authenticate_and_create_session(self, identifier: str, password: str):
        """Verify credentials and create their session under the account-row lock.

        A password reset updates the same row before revoking sessions. Serializing
        both operations means a stale-password login cannot insert its session
        after reset has completed.
        """
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            suffix = " FOR UPDATE" if self.engine_type == "mysql" else ""
            cur.execute(self._translate_query(
                "SELECT * FROM users WHERE LOWER(email)=LOWER(%s) LIMIT 1" + suffix
            ), (str(identifier).strip(),))
            row = cur.fetchone()
            if not row:
                cur.execute(self._translate_query(
                    "SELECT * FROM users WHERE UPPER(linking_code)=UPPER(%s) LIMIT 1" + suffix
                ), (str(identifier).strip(),))
                row = cur.fetchone()
            user = dict(row) if row and not isinstance(row, dict) else row
            if not user:
                conn.rollback()
                return None, None, "No account found with this email address."

            stored_hash = user.get("password_hash", "")
            if stored_hash.startswith(("scrypt:", "pbkdf2:")):
                if not check_password_hash(stored_hash, password):
                    conn.rollback()
                    return None, None, "Incorrect password. Please try again."
            else:
                if stored_hash != password:
                    conn.rollback()
                    return None, None, "Incorrect password. Please try again."
                stored_hash = generate_password_hash(password)
                cur.execute(self._translate_query(
                    "UPDATE users SET password_hash=%s WHERE id=%s"
                ), (stored_hash, user["id"]))
                user["password_hash"] = stored_hash

            token = f"tws_{uuid.uuid4().hex}_{int(datetime.datetime.now().timestamp())}"
            expires_at = datetime.datetime.now() + datetime.timedelta(days=30)
            cur.execute(self._translate_query(
                "INSERT INTO sessions (token,user_id,expires_at) VALUES (%s,%s,%s)"
            ), (token, user["id"], expires_at.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            return user, token, None
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def update_user_password(self, email: str, new_password: str):
        email_clean = email.strip().lower()
        new_hash = generate_password_hash(new_password)
        self.execute("UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE LOWER(email) = LOWER(%s)", (new_hash, email_clean))
        return True

    def reset_user_password_and_revoke_sessions(self, user_id: str, new_password: str):
        """Update credentials and revoke every active session atomically."""
        new_hash = generate_password_hash(new_password)
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            cur.execute(self._translate_query(
                "UPDATE users SET password_hash=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s"
            ), (new_hash, user_id))
            if cur.rowcount != 1:
                raise ValueError("Password reset account no longer exists")
            cur.execute(self._translate_query("DELETE FROM sessions WHERE user_id=%s"), (user_id,))
            conn.commit()
            return True
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def create_session(self, user_id: str):
        token = f"tws_{uuid.uuid4().hex}_{int(datetime.datetime.now().timestamp())}"
        expires_at = datetime.datetime.now() + datetime.timedelta(days=30)
        self.execute("""
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (%s, %s, %s)
        """, (token, user_id, expires_at.strftime("%Y-%m-%d %H:%M:%S")))
        return token

    def _lock_task_owner(self, cursor, user_id: str):
        """Lock the same account row used by academic collection replacement."""
        suffix = " FOR UPDATE" if self.engine_type == "mysql" else ""
        cursor.execute(self._translate_query(
            "SELECT id FROM users WHERE id=%s" + suffix
        ), (user_id,))
        if not cursor.fetchone():
            raise ValueError("Student account was not found")

    def get_user_by_token(self, token: str):
        if not token:
            return None
        sess = self.fetchone("SELECT * FROM sessions WHERE token = %s", (token.strip(),))
        if not sess:
            return None
        expires_at = sess.get("expires_at")
        if expires_at:
            try:
                if isinstance(expires_at, datetime.datetime):
                    expiry = expires_at
                else:
                    expiry = datetime.datetime.fromisoformat(str(expires_at))
                if datetime.datetime.now() > expiry:
                    self.delete_session(token)
                    return None
            except (TypeError, ValueError):
                # An unparsable expiry is not grounds to trust the session.
                self.delete_session(token)
                return None
        return self.get_user_by_id(sess["user_id"])

    def delete_session(self, token: str):
        if token:
            self.execute("DELETE FROM sessions WHERE token = %s", (token.strip(),))

    # -------------------------------------------------------------------------
    # USER-SCOPED DATA ACCESS & ACADEMIC STORAGE
    # -------------------------------------------------------------------------
    def get_user_data_versions(self, user_id: str):
        row = self.fetchone("SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id = %s", (user_id,))
        return {
            "academic_revision": int((row or {}).get("academic_version", 1)),
            "calendar_revision": int((row or {}).get("calendar_version", 1)),
        }

    def _lock_user_data_versions_for_update(self, cursor, user_id: str):
        query = "INSERT IGNORE INTO user_data_versions (user_id) VALUES (%s)"
        cursor.execute(self._translate_query(query), (user_id,))
        suffix = " FOR UPDATE" if self.engine_type == "mysql" else ""
        cursor.execute(self._translate_query(
            f"SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id = %s{suffix}"
        ), (user_id,))
        row = cursor.fetchone()
        return dict(row) if not isinstance(row, dict) else row

    def _lock_user_data_versions(self, cursor, user_id: str, expected_column: str, expected_revision: int):
        if expected_column not in ("academic_version", "calendar_version"):
            raise ValueError("Invalid data revision category")
        row = self._lock_user_data_versions_for_update(cursor, user_id)
        current = int(row[expected_column])
        if current != int(expected_revision):
            raise ConcurrentUpdateError("Saved academic data changed since it was loaded. Reload before saving again.")

    def update_student_profile_fields(self, user_id: str, name: str, dob: str, age: int,
                                      is_minor: bool, role: str, guardian_email: str,
                                      daily_hours: float, college: str, grade_level: str,
                                      course: str, semester: str, expected_revision: int):
        """Serialize settings-profile writes with academic collection replacement."""
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_user_data_versions(cur, user_id, "academic_version", expected_revision)
            cur.execute(self._translate_query("""UPDATE users
                SET name=%s,dob=%s,age=%s,is_minor=%s,role=%s,guardian_email=%s,
                    daily_study_hours=%s,college=%s,grade_level=%s,updated_at=CURRENT_TIMESTAMP
                WHERE id=%s"""),
                (name, dob, age, 1 if is_minor else 0, role, guardian_email,
                 daily_hours, college, grade_level, user_id))
            user_updated = cur.rowcount > 0
            cur.execute(self._translate_query("""UPDATE student_profiles
                SET student_name=%s,college=%s,course=%s,semester=%s WHERE user_id=%s"""),
                (name, college, course, semester, user_id))
            profile_updated = cur.rowcount > 0
            if user_updated or profile_updated:
                cur.execute(self._translate_query(
                    "UPDATE user_data_versions SET academic_version=academic_version+1 WHERE user_id=%s"
                ), (user_id,))
            cur.execute(self._translate_query(
                "SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id=%s"
            ), (user_id,))
            versions = dict(cur.fetchone())
            conn.commit()
            return {"academic_revision": int(versions["academic_version"]),
                    "calendar_revision": int(versions["calendar_version"])}
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def save_user_academic_state(self, user_id: str, profile: dict, subjects: list, classes: list, tasks: list = None, preserve_existing_tasks: bool = False, expected_revision: int = None, calendar_events: list = None, calendar_exams: list = None, expected_calendar_revision: int = None, compatibility_tasks: list = None, exam_imports: list = None):
        """Atomically replace one student's normalized academic and optional calendar data.

        Request-supplied identifiers are preserved only when they are not owned by a
        different account. References to subjects outside this submitted student-owned
        subject set are discarded to prevent cross-account foreign-ID references.
        Returns normalized records containing the identifiers actually stored. When
        expected revisions are supplied, a concurrent writer causes a rollback.
        """
        if not user_id:
            raise ValueError("A student user_id is required")
        if not isinstance(profile, dict) or not isinstance(subjects, list) or not isinstance(classes, list):
            raise ValueError("Profile must be an object and subjects/classes must be lists")
        if tasks is not None and not isinstance(tasks, list):
            raise ValueError("Tasks must be a list")
        if compatibility_tasks is not None and (not isinstance(compatibility_tasks, list) or len(compatibility_tasks) > 2000):
            raise ValueError("Compatibility tasks must be a list of at most 2000 records")
        if exam_imports is not None and (not isinstance(exam_imports, list) or len(exam_imports) > 1000):
            raise ValueError("Imported exams must be a list of at most 1000 records")
        if calendar_events is not None and (not isinstance(calendar_events, list) or len(calendar_events) > 2000):
            raise ValueError("Calendar events must be a list of at most 2000 records")
        if calendar_exams is not None and (not isinstance(calendar_exams, list) or len(calendar_exams) > 1000):
            raise ValueError("Calendar exams must be a list of at most 1000 records")
        if len(subjects) > 300 or len(classes) > 2000 or (tasks is not None and len(tasks) > 2000):
            raise ValueError("Academic payload exceeds the supported record limit")

        normalized_subjects = []
        normalized_classes = []
        normalized_tasks = []
        subject_id_map = {}
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()

            if expected_revision is not None:
                self._lock_user_data_versions(cur, user_id, "academic_version", expected_revision)
            if expected_calendar_revision is not None:
                self._lock_user_data_versions(cur, user_id, "calendar_version", expected_calendar_revision)
            self._lock_task_owner(cur, user_id)

            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
                return cur

            def fetchone(sql, params=()):
                execute(sql, params)
                row = cur.fetchone()
                if row is None:
                    return None
                return dict(row) if not isinstance(row, dict) else row

            def safe_id(table, requested, prefix):
                candidate = str(requested or "").strip()[:64]
                if candidate:
                    found = fetchone(f"SELECT id, user_id FROM {table} WHERE id = %s", (candidate,))
                    if found and str(found.get("user_id")) != str(user_id):
                        candidate = ""
                if not candidate:
                    candidate = f"{prefix}_{uuid.uuid4().hex[:24]}"
                    while fetchone(f"SELECT id FROM {table} WHERE id = %s", (candidate,)):
                        candidate = f"{prefix}_{uuid.uuid4().hex[:24]}"
                return candidate

            prof = fetchone("SELECT id FROM student_profiles WHERE user_id = %s LIMIT 1", (user_id,))
            p_name = str(profile.get("student_name") or "")[:191]
            p_college = str(profile.get("college") or "")[:191]
            p_course = str(profile.get("course") or "")[:191]
            p_semester = str(profile.get("semester") or "")[:64]
            p_spec = str(profile.get("specialization") or "cs")[:64]
            p_year = str(profile.get("academic_year") or "")[:64]
            if prof:
                execute("""UPDATE student_profiles SET student_name=%s, college=%s, course=%s,
                    semester=%s, specialization=%s, academic_year=%s WHERE user_id=%s""",
                    (p_name, p_college, p_course, p_semester, p_spec, p_year, user_id))
            else:
                execute("""INSERT INTO student_profiles
                    (id,user_id,student_name,college,course,semester,specialization,academic_year)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (f"prof_{uuid.uuid4().hex[:24]}", user_id, p_name, p_college, p_course, p_semester, p_spec, p_year))
            grade_str = f"{p_course} ({p_semester})" if p_course and p_semester else p_course
            execute("UPDATE users SET college=%s, grade_level=%s, name=CASE WHEN %s <> '' THEN %s ELSE name END WHERE id=%s",
                    (p_college, grade_str, p_name, p_name, user_id))

            # Academic-profile saves may include suggested tasks for a new student.
            # Once any task exists, retain the student's collection unchanged.
            # The users-row update above serializes same-user saves in MySQL; SQLite
            # already holds its immediate write lock for this transaction.
            if tasks is not None and preserve_existing_tasks:
                existing_task = fetchone("SELECT id FROM tasks WHERE user_id = %s LIMIT 1", (user_id,))
                if existing_task:
                    tasks = None
                elif compatibility_tasks:
                    # The old JSON-backed application may be the only place the
                    # student's existing task IDs/progress have been stored.
                    # Import those under this same transaction before suggestions.
                    tasks = compatibility_tasks

            # Resolve IDs before deleting old rows so identifiers belonging to other
            # students are never reused for this student's replacement records.
            for item in subjects:
                if not isinstance(item, dict):
                    raise ValueError("Each subject must be an object")
                old_id = str(item.get("id") or "")
                sid = safe_id("subjects", old_id, "sub")
                if old_id:
                    subject_id_map[old_id] = sid
                normalized_subjects.append({**item, "id": sid})
            for item in classes:
                if not isinstance(item, dict):
                    raise ValueError("Each class must be an object")
                normalized_classes.append({**item, "id": safe_id("classes", item.get("id"), "cls")})
            if tasks is not None:
                for item in tasks:
                    if not isinstance(item, dict):
                        raise ValueError("Each task must be an object")
                    normalized_tasks.append({**item, "id": safe_id("tasks", item.get("id"), "task")})

            execute("DELETE FROM classes WHERE user_id = %s", (user_id,))
            execute("DELETE FROM subjects WHERE user_id = %s", (user_id,))
            for item in normalized_subjects:
                execute("""INSERT INTO subjects
                    (id,user_id,name,code,credits,target_percentage,target_grade,professor,teacher,room,color,type)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (item["id"], user_id, str(item.get("name", "Subject"))[:191], str(item.get("code", ""))[:64],
                     safe_int(item.get("credits"), 3), safe_float(item.get("target_percentage"), 85.0),
                     str(item.get("target_grade") or "A")[:16], str(item.get("teacher") or item.get("professor") or "")[:191],
                     str(item.get("teacher") or item.get("professor") or "")[:191], str(item.get("room", ""))[:64],
                     str(item.get("color", "#00C4CC"))[:32], str(item.get("type", "Lecture"))[:64]))

            for item in normalized_classes:
                source_sid = str(item.get("subject_id") or "")
                resolved_sid = subject_id_map.get(source_sid, "") if source_sid else ""
                subj = str(item.get("subject") or item.get("subject_name") or "Class")[:191]
                day = str(item.get("day", "Monday"))[:32]
                st = str(item.get("start_time", "10:00"))[:32]
                et = str(item.get("end_time", "11:30"))[:32]
                time_slot = str(item.get("time") or item.get("time_slot") or f"{st} - {et}")[:64]
                teacher = str(item.get("teacher") or item.get("professor") or "")[:191]
                execute("""INSERT INTO classes
                    (id,user_id,subject_id,subject_name,subject,day,time_slot,time,start_time,end_time,room,professor,teacher,color,type,week_type)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (item["id"], user_id, resolved_sid, subj, subj, day, time_slot, time_slot, st, et,
                     str(item.get("room", ""))[:64], teacher, teacher, str(item.get("color", "#00C4CC"))[:32],
                     str(item.get("type", "Lecture"))[:64], str(item.get("week_type", "All"))[:64]))
                item["subject_id"] = resolved_sid

            if tasks is not None:
                execute("DELETE FROM tasks WHERE user_id = %s", (user_id,))
                for item in normalized_tasks:
                    source_sid = str(item.get("subject_id") or "")
                    resolved_sid = subject_id_map.get(source_sid, "") if source_sid else ""
                    title = str(item.get("title", "Task"))[:255]
                    execute("""INSERT INTO tasks
                        (id,user_id,subject_id,subject_name,title,description,due_date,priority,status,points_reward,verified,verified_file,quiz_score,verified_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (item["id"], user_id, resolved_sid, str(item.get("subject_name") or item.get("subject") or "Coursework")[:191],
                         title, str(item.get("proof_required") or item.get("description") or ""), str(item.get("due_date") or ""),
                         str(item.get("priority", "High"))[:32], str(item.get("status", "Pending"))[:64],
                         safe_int(item.get("points_reward", item.get("points", 100)), 100),
                         1 if item.get("verified") else 0, str(item.get("verified_file") or ""),
                         str(item.get("quiz_score") or ""), str(item.get("verified_at") or "")))
                    item["subject_id"] = resolved_sid

            # Document imports add exams; they never replace the student's existing
            # exam collection. The academic revision lock above serializes imports
            # with other academic writes, and this all runs in the same transaction.
            if exam_imports is not None:
                existing_exam_rows = execute(
                    "SELECT id, title, subject_name, exam_date FROM exams WHERE user_id = %s",
                    (user_id,),
                ).fetchall()
                existing_exam_keys = {
                    (str(row.get("title") or "").strip().casefold(),
                     str(row.get("subject_name") or "").strip().casefold(),
                     str(row.get("exam_date") or "").strip()[:10])
                    for row in (dict(value) if not isinstance(value, dict) else value for value in existing_exam_rows)
                }
                for raw_exam in exam_imports:
                    if not isinstance(raw_exam, dict):
                        raise ValueError("Each imported exam must be an object")
                    exam = dict(raw_exam)
                    title = str(exam.get("title") or exam.get("subject_name") or "Exam").strip()[:255]
                    subject_name = str(exam.get("subject_name") or exam.get("subject") or "").strip()[:191]
                    exam_date = str(exam.get("exam_date") or exam.get("date") or "").strip()[:64]
                    exam_key = (title.casefold(), subject_name.casefold(), exam_date[:10])
                    if exam_key in existing_exam_keys:
                        continue

                    exam_id = str(exam.get("id") or f"ex_{uuid.uuid4().hex[:24]}")[:64]
                    existing_id = fetchone("SELECT user_id FROM exams WHERE id = %s", (exam_id,))
                    if existing_id and str(existing_id.get("user_id")) != str(user_id):
                        exam_id = f"ex_{uuid.uuid4().hex[:24]}"
                    elif existing_id:
                        existing_exam_keys.add(exam_key)
                        continue
                    execute("""INSERT INTO exams
                        (id,user_id,subject_id,subject_name,title,exam_date,weight_pct,target_score,syllabus_summary)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (exam_id, user_id, str(exam.get("subject_id") or "")[:64], subject_name,
                         title, exam_date, safe_float(exam.get("weight_pct", exam.get("weight", 30.0)), 30.0),
                         safe_float(exam.get("target_score", exam.get("target", 85.0)), 85.0),
                         str(exam.get("syllabus_summary") or exam.get("syllabus") or "")))
                    existing_exam_keys.add(exam_key)

            if calendar_events is not None:
                execute("DELETE FROM academic_calendar_events WHERE user_id = %s", (user_id,))
                for item in calendar_events:
                    if not isinstance(item, dict):
                        raise ValueError("Each calendar event must be an object")
                    item_id = str(item.get("id") or f"evt_{uuid.uuid4().hex[:24]}")[:64]
                    existing = fetchone("SELECT user_id FROM academic_calendar_events WHERE id = %s", (item_id,))
                    if existing and str(existing.get("user_id")) != str(user_id):
                        item_id = f"evt_{uuid.uuid4().hex[:24]}"
                    title = str(item.get("title") or item.get("name") or "Academic event")[:255]
                    event_date = str(item.get("date") or item.get("event_date") or "")[:64]
                    event_type = str(item.get("type") or "event")[:64]
                    execute("""INSERT INTO academic_calendar_events
                        (id,user_id,event_date,title,event_type,payload_json) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (item_id, user_id, event_date, title, event_type, json.dumps(item, ensure_ascii=False)))

            if calendar_exams is not None:
                execute("DELETE FROM academic_calendar_exams WHERE user_id = %s", (user_id,))
                for item in calendar_exams:
                    if not isinstance(item, dict):
                        raise ValueError("Each calendar exam must be an object")
                    item_id = str(item.get("id") or f"calex_{uuid.uuid4().hex[:24]}")[:64]
                    existing = fetchone("SELECT user_id FROM academic_calendar_exams WHERE id = %s", (item_id,))
                    if existing and str(existing.get("user_id")) != str(user_id):
                        item_id = f"calex_{uuid.uuid4().hex[:24]}"
                    exam_date = str(item.get("date") or item.get("exam_date") or "")[:64]
                    title = str(item.get("title") or item.get("name") or "Exam")[:255]
                    subject = str(item.get("subject") or item.get("subject_name") or "")[:191]
                    execute("""INSERT INTO academic_calendar_exams
                        (id,user_id,exam_date,title,subject_name,payload_json) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (item_id, user_id, exam_date, title, subject, json.dumps(item, ensure_ascii=False)))

            if expected_revision is not None:
                execute("UPDATE user_data_versions SET academic_version = academic_version + 1 WHERE user_id = %s", (user_id,))
            if expected_calendar_revision is not None:
                execute("UPDATE user_data_versions SET calendar_version = calendar_version + 1 WHERE user_id = %s", (user_id,))
            versions = None
            if expected_revision is not None or expected_calendar_revision is not None:
                versions = fetchone("SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id = %s", (user_id,))
            conn.commit()
            return {"academic_profile": {**profile, "student_name": p_name, "college": p_college, "course": p_course,
                                          "semester": p_semester, "specialization": p_spec, "academic_year": p_year},
                    "subjects": normalized_subjects, "classes": normalized_classes,
                    "tasks": normalized_tasks if tasks is not None else None,
                    "academic_revision": int(versions["academic_version"]) if versions else None,
                    "calendar_revision": int(versions["calendar_version"]) if versions else None}
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def save_user_calendar(self, user_id: str, events: list = None, exams: list = None, expected_revision: int = None):
        """Atomically replace supplied calendar collections for the authenticated user."""
        if not user_id:
            raise ValueError("A student user_id is required")
        if events is not None and (not isinstance(events, list) or len(events) > 2000):
            raise ValueError("Calendar events must be a list of at most 2000 records")
        if exams is not None and (not isinstance(exams, list) or len(exams) > 1000):
            raise ValueError("Calendar exams must be a list of at most 1000 records")
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
            if expected_revision is not None:
                self._lock_user_data_versions(cur, user_id, "calendar_version", expected_revision)
            if events is not None:
                execute("DELETE FROM academic_calendar_events WHERE user_id = %s", (user_id,))
                for item in events:
                    if not isinstance(item, dict):
                        raise ValueError("Each calendar event must be an object")
                    item_id = str(item.get("id") or f"evt_{uuid.uuid4().hex[:24]}")[:64]
                    execute("SELECT user_id FROM academic_calendar_events WHERE id = %s", (item_id,))
                    existing = cur.fetchone()
                    if existing:
                        existing_map = dict(existing) if not isinstance(existing, dict) else existing
                        if str(existing_map.get("user_id")) != str(user_id):
                            item_id = f"evt_{uuid.uuid4().hex[:24]}"
                    title = str(item.get("title") or item.get("name") or "Academic event")[:255]
                    ev_date = str(item.get("date") or item.get("event_date") or "")[:64]
                    event_type = str(item.get("type") or "event")[:64]
                    execute("""INSERT INTO academic_calendar_events
                        (id,user_id,event_date,title,event_type,payload_json) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (item_id, user_id, ev_date, title, event_type, json.dumps(item, ensure_ascii=False)))
            if exams is not None:
                execute("DELETE FROM academic_calendar_exams WHERE user_id = %s", (user_id,))
                for item in exams:
                    if not isinstance(item, dict):
                        raise ValueError("Each calendar exam must be an object")
                    item_id = str(item.get("id") or f"calex_{uuid.uuid4().hex[:24]}")[:64]
                    execute("SELECT user_id FROM academic_calendar_exams WHERE id = %s", (item_id,))
                    existing = cur.fetchone()
                    if existing:
                        existing_map = dict(existing) if not isinstance(existing, dict) else existing
                        if str(existing_map.get("user_id")) != str(user_id):
                            item_id = f"calex_{uuid.uuid4().hex[:24]}"
                    ex_date = str(item.get("date") or item.get("exam_date") or "")[:64]
                    title = str(item.get("title") or item.get("name") or "Exam")[:255]
                    subject = str(item.get("subject") or item.get("subject_name") or "")[:191]
                    execute("""INSERT INTO academic_calendar_exams
                        (id,user_id,exam_date,title,subject_name,payload_json) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (item_id, user_id, ex_date, title, subject, json.dumps(item, ensure_ascii=False)))
            if expected_revision is not None:
                execute("UPDATE user_data_versions SET calendar_version = calendar_version + 1 WHERE user_id = %s", (user_id,))
            versions = None
            if expected_revision is not None:
                execute("SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id = %s", (user_id,))
                row = cur.fetchone()
                versions = dict(row) if not isinstance(row, dict) else row
            conn.commit()
            if versions:
                return {"academic_revision": int(versions["academic_version"]),
                        "calendar_revision": int(versions["calendar_version"])}
            return None
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def get_user_calendar(self, user_id: str):
        def decode(rows):
            values = []
            for row in rows:
                try:
                    value = json.loads(row.get("payload_json") or "{}")
                    if isinstance(value, dict):
                        values.append(value)
                except (ValueError, TypeError):
                    continue
            return values
        events = self.fetchall("SELECT payload_json FROM academic_calendar_events WHERE user_id = %s ORDER BY event_date ASC", (user_id,))
        exams = self.fetchall("SELECT payload_json FROM academic_calendar_exams WHERE user_id = %s ORDER BY exam_date ASC", (user_id,))
        return {"calendar_events": decode(events), "calendar_exams": decode(exams)}

    def get_user_academic_state(self, user_id: str):
        user = self.get_user_by_id(user_id)
        if not user:
            return {}

        profile = self.fetchone("SELECT * FROM student_profiles WHERE user_id = %s", (user_id,))
        subjects = self.fetchall("SELECT * FROM subjects WHERE user_id = %s ORDER BY name ASC", (user_id,))
        classes = self.fetchall("SELECT * FROM classes WHERE user_id = %s ORDER BY day ASC, time_slot ASC", (user_id,))

        for s in subjects:
            s["teacher"] = s.get("teacher") or s.get("professor") or "Faculty"
            s["professor"] = s["teacher"]
            s["type"] = s.get("type") or "Lecture"

        for c in classes:
            c["subject"] = c.get("subject") or c.get("subject_name") or "Class"
            c["subject_name"] = c["subject"]
            c["time"] = c.get("time") or c.get("time_slot") or ""
            c["time_slot"] = c["time"]
            c["teacher"] = c.get("teacher") or c.get("professor") or "Faculty"
            c["professor"] = c["teacher"]
            c["type"] = c.get("type") or "Lecture"
            c["week_type"] = c.get("week_type") or "All"
            c["start_time"] = c.get("start_time") or ""
            c["end_time"] = c.get("end_time") or ""

        tasks = self.fetchall("SELECT * FROM tasks WHERE user_id = %s ORDER BY status ASC, due_date ASC", (user_id,))
        for t in tasks:
            t["subject"] = t.get("subject_name") or t.get("subject") or "Coursework"
            t["subject_name"] = t["subject"]
            t["proof_status"] = "verified" if t.get("verified") else "pending"
            t["points"] = t.get("points_reward") or 100
            t["due"] = f"Due: {t.get('due_date')}" if t.get("due_date") else "Upcoming"

        exams = self.fetchall("SELECT * FROM exams WHERE user_id = %s ORDER BY exam_date ASC", (user_id,))
        grades = self.fetchall("SELECT * FROM grades WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        patterns = self.fetchall("SELECT * FROM behavior_patterns WHERE user_id = %s AND is_active = 1", (user_id,))
        goals = self.fetchall("SELECT * FROM goals WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        study_sessions = self.fetchall("SELECT * FROM study_sessions WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        permissions = self.fetchone("SELECT * FROM permissions WHERE user_id = %s", (user_id,))
        privacy = self.fetchone("SELECT * FROM privacy_settings WHERE user_id = %s", (user_id,))
        notifications = self.fetchall("SELECT * FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 20", (user_id,))

        # Map subject targets dict
        subject_targets = {s["id"]: s.get("target_grade") or "A" for s in subjects}

        return {
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "dob": user.get("dob", ""),
                "age": user.get("age", 20),
                "is_minor": bool(user.get("is_minor")),
                "role": user.get("role", "student"),
                "points": user.get("points", 100),
                "streak_days": user.get("streak_days", 1),
                "daily_study_hours": user.get("daily_study_hours", 3.0),
                "focus_duration_minutes": user.get("focus_duration_minutes", 45),
                "college": user.get("college", ""),
                "grade_level": user.get("grade_level", ""),
                "guardian_email": user.get("guardian_email", ""),
                "linking_code": user.get("linking_code", "TS-LINK-8921")
            },
            "academic_profile": profile or {},
            "subjects": subjects or [],
            "classes": classes or [],
            "tasks": tasks or [],
            "exams": exams or [],
            "grades": grades or [],
            "goals": goals or [],
            "study_sessions": study_sessions or [],
            "behavior_patterns": patterns or [],
            "parent_controls": permissions or {},
            "privacy_controls": privacy or {
                "academic_calendar": 1,
                "biometric_telemetry": 1,
                "parent_live_nudges": 1,
                "allow_research_benchmarking": 0
            },
            "subject_targets": subject_targets,
            "notifications": notifications or []
        }

    # -------------------------------------------------------------------------
    # TASKS MANAGEMENT
    # -------------------------------------------------------------------------
    def add_task(self, user_id: str, task: dict):
        if not user_id or not isinstance(task, dict):
            raise ValueError("A student owner and task object are required")
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_task_owner(cur, user_id)
            t_id = str(task.get("id") or f"t_{uuid.uuid4().hex[:24]}")[:64]
            cur.execute(self._translate_query("SELECT user_id FROM tasks WHERE id=%s"), (t_id,))
            existing = cur.fetchone()
            if existing:
                existing = dict(existing) if not isinstance(existing, dict) else existing
                if str(existing.get("user_id")) != str(user_id):
                    t_id = f"t_{uuid.uuid4().hex[:24]}"
            cur.execute(self._translate_query("""INSERT INTO tasks (
                id,user_id,subject_id,subject_name,title,description,due_date,priority,status,points_reward,verified
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""), (
                t_id, user_id, str(task.get("subject_id") or "")[:64],
                str(task.get("subject") or task.get("subject_name") or "Coursework")[:191],
                str(task.get("title") or "Task")[:255], str(task.get("description") or task.get("proof_required") or ""),
                str(task.get("due_date") or "")[:64], str(task.get("priority") or "High")[:32],
                str(task.get("status") or "Pending")[:64], safe_int(task.get("points_reward", task.get("points", 100)), 100),
                1 if task.get("verified") else 0
            ))
            conn.commit()
            return t_id
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def delete_task(self, user_id: str, task_id: str):
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_task_owner(cur, user_id)
            cur.execute(self._translate_query(
                "DELETE FROM tasks WHERE id = %s AND user_id = %s"
            ), (task_id, user_id))
            deleted = getattr(cur, "rowcount", 0) == 1
            conn.commit()
            return deleted
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def replace_user_tasks(self, user_id: str, tasks: list):
        """Replace a student's task list atomically; every row is scoped to that user."""
        if not user_id or not isinstance(tasks, list) or len(tasks) > 2000:
            raise ValueError("A student user_id and a valid task list are required")
        conn = self.get_connection()
        normalized = []
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_task_owner(cur, user_id)
            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
                return cur
            execute("DELETE FROM tasks WHERE user_id = %s", (user_id,))
            seen = set()
            for raw in tasks:
                if not isinstance(raw, dict):
                    raise ValueError("Each task must be an object")
                item = dict(raw)
                tid = str(item.get("id") or f"task_{uuid.uuid4().hex[:24]}")[:64]
                if tid in seen:
                    tid = f"task_{uuid.uuid4().hex[:24]}"
                # Reject reuse of an ID owned by another student.
                execute("SELECT user_id FROM tasks WHERE id = %s", (tid,))
                found = cur.fetchone()
                if found:
                    found_map = dict(found) if not isinstance(found, dict) else found
                    if str(found_map.get("user_id")) != str(user_id):
                        tid = f"task_{uuid.uuid4().hex[:24]}"
                seen.add(tid)
                item["id"] = tid
                cur.execute(self._translate_query("""INSERT INTO tasks
                    (id,user_id,subject_id,subject_name,title,description,due_date,priority,status,points_reward,verified,verified_file,quiz_score,verified_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""), (
                    tid, user_id, str(item.get("subject_id") or "")[:64],
                    str(item.get("subject_name") or item.get("subject") or "Coursework")[:191],
                    str(item.get("title") or "Task")[:255], str(item.get("proof_required") or item.get("description") or ""),
                    str(item.get("due_date") or "")[:64], str(item.get("priority") or "High")[:32],
                    str(item.get("status") or "Pending")[:64], safe_int(item.get("points_reward", item.get("points", 100)), 100),
                    1 if item.get("verified") else 0, str(item.get("verified_file") or ""),
                    str(item.get("quiz_score") or ""), str(item.get("verified_at") or "")
                ))
                normalized.append(item)
            conn.commit()
            return normalized
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def add_generated_tasks(self, user_id: str, tasks: list):
        """Add generated suggestions without replacing or resetting saved tasks.

        The user row lock serializes simultaneous generation requests on MySQL;
        SQLite's immediate transaction provides the same per-database exclusion.
        Suggestions with an existing (subject, title) pair are skipped.
        """
        if not user_id or not isinstance(tasks, list) or len(tasks) > 2000:
            raise ValueError("A student user_id and a valid task list are required")
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()

            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
                return cur

            self._lock_task_owner(cur, user_id)
            execute("SELECT id, subject_name, title FROM tasks WHERE user_id = %s", (user_id,))
            existing = cur.fetchall()
            existing_rows = [dict(row) if not isinstance(row, dict) else row for row in existing]
            keys = {(str(row.get("subject_name") or ""), str(row.get("title") or "")) for row in existing_rows}
            for raw in tasks:
                if not isinstance(raw, dict):
                    raise ValueError("Each task must be an object")
                item = dict(raw)
                subject = str(item.get("subject_name") or item.get("subject") or "Coursework")[:191]
                title = str(item.get("title") or "Task")[:255]
                if (subject, title) in keys:
                    continue
                task_id = str(item.get("id") or f"task_{uuid.uuid4().hex[:24]}")[:64]
                execute("SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                found = cur.fetchone()
                if found:
                    found_map = dict(found) if not isinstance(found, dict) else found
                    if str(found_map.get("user_id")) != str(user_id):
                        task_id = f"task_{uuid.uuid4().hex[:24]}"
                execute("""INSERT INTO tasks
                    (id,user_id,subject_id,subject_name,title,description,due_date,priority,status,
                     points_reward,verified,verified_file,quiz_score,verified_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (task_id, user_id, str(item.get("subject_id") or "")[:64], subject, title,
                     str(item.get("proof_required") or item.get("description") or ""),
                     str(item.get("due_date") or "")[:64], str(item.get("priority") or "High")[:32],
                     str(item.get("status") or "Pending")[:64],
                     safe_int(item.get("points_reward", item.get("points", 100)), 100),
                     1 if item.get("verified") else 0, str(item.get("verified_file") or ""),
                     str(item.get("quiz_score") or ""), str(item.get("verified_at") or "")))
                item.update({"id": task_id, "subject_name": subject, "title": title})
                existing_rows.append(item)
                keys.add((subject, title))
            conn.commit()
            return existing_rows
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def get_user_tasks(self, user_id: str):
        return self.fetchall("SELECT * FROM tasks WHERE user_id = %s ORDER BY created_at DESC", (user_id,))

    def verify_task_proof(self, user_id: str, task_id: str, filename: str, quiz_score: str, earned_points: int):
        """Verify a task once, and atomically award its points only to its owner."""
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_task_owner(cur, user_id)
            def execute(sql, params=()):
                cur.execute(self._translate_query(sql), params)
                return cur
            execute("SELECT verified FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return "not_found"
            row = dict(row) if not isinstance(row, dict) else row
            if row.get("verified"):
                conn.rollback()
                return "already_verified"
            now_str = datetime.datetime.now().isoformat()
            execute("""UPDATE tasks SET status='Verified & Done',verified=1,verified_file=%s,
                quiz_score=%s,verified_at=%s WHERE id=%s AND user_id=%s AND verified=0""",
                (str(filename)[:255], str(quiz_score)[:32], now_str, task_id, user_id))
            if getattr(cur, "rowcount", 0) != 1:
                conn.rollback()
                return "already_verified"
            execute("UPDATE users SET points = points + %s, streak_days = streak_days + 1 WHERE id = %s", (max(0, safe_int(earned_points)), user_id))
            notif_id = f"notif_{uuid.uuid4().hex[:10]}"
            execute("""INSERT INTO notifications (id,user_id,title,description,type)
                VALUES (%s,%s,%s,%s,'reward')""",
                (notif_id, user_id, "Proof Verified! Points Awarded", f"Task {task_id} verified with quiz score {quiz_score}."))
            conn.commit()
            return "verified"
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # GRADES & TARGETS
    # -------------------------------------------------------------------------
    def get_user_subject(self, user_id: str, subject_id=None, subject_name=None):
        """Resolve a subject only within the authenticated user's records."""
        if subject_id:
            rows = self.fetchall(
                "SELECT id, name FROM subjects WHERE id = %s AND user_id = %s LIMIT 1",
                (subject_id, user_id),
            )
            if rows:
                return rows[0]

        if subject_name:
            rows = self.fetchall(
                "SELECT id, name FROM subjects WHERE name = %s AND user_id = %s LIMIT 1",
                (subject_name, user_id),
            )
            if rows:
                return rows[0]

        return None

    def add_grade(self, user_id: str, grade_data: dict):
        g_id = grade_data.get("id") or f"gr_{uuid.uuid4().hex[:10]}"
        self.execute("""
            INSERT INTO grades (
                id, user_id, subject_id, subject_name, assessment_type, title,
                marks_obtained, max_marks, percentage, grade, term
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            g_id, user_id, grade_data.get("subject_id", ""),
            grade_data.get("subject", grade_data.get("subject_name", "Module")),
            grade_data.get("assessment_type", grade_data.get("type", "Assignment")),
            grade_data.get("title", "Exam/Assignment"),
            safe_float(grade_data.get("marks_obtained", grade_data.get("score", 85.0))),
            safe_float(grade_data.get("max_marks", 100.0)),
            safe_float(grade_data.get("percentage", 85.0)),
            grade_data.get("grade", "A"),
            grade_data.get("term", "Semester 6")
        ))
        return g_id

    def delete_grade(self, user_id: str, grade_id: str):
        cur = self.execute("DELETE FROM grades WHERE id = %s AND user_id = %s", (grade_id, user_id))
        return getattr(cur, "rowcount", 0) == 1


    def set_subject_target(self, user_id: str, subject_id: str, target: str, expected_revision: int):
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            self._lock_user_data_versions(cur, user_id, "academic_version", expected_revision)
            cur.execute(self._translate_query(
                "UPDATE subjects SET target_grade = %s WHERE id = %s AND user_id = %s"
            ), (target, subject_id, user_id))
            changed = cur.rowcount == 1
            if not changed:
                cur.execute(self._translate_query(
                    "SELECT id FROM subjects WHERE id = %s AND user_id = %s LIMIT 1"
                ), (subject_id, user_id))
                exists = cur.fetchone() is not None
            else:
                exists = True
                cur.execute(self._translate_query(
                    "UPDATE user_data_versions SET academic_version=academic_version+1 WHERE user_id=%s"
                ), (user_id,))
            cur.execute(self._translate_query(
                "SELECT academic_version, calendar_version FROM user_data_versions WHERE user_id=%s"
            ), (user_id,))
            versions = dict(cur.fetchone())
            conn.commit()
            return exists, {"academic_revision": int(versions["academic_version"]),
                             "calendar_revision": int(versions["calendar_version"])}
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def get_user_grades(self, user_id: str):
        return self.fetchall("SELECT * FROM grades WHERE user_id = %s ORDER BY created_at DESC", (user_id,))

    # -------------------------------------------------------------------------
    # EXAMS
    # -------------------------------------------------------------------------
    def add_exam(self, user_id: str, exam_data: dict):
        e_id = exam_data.get("id") or f"ex_{uuid.uuid4().hex[:10]}"
        self.execute("""
            INSERT INTO exams (id, user_id, subject_id, subject_name, title, exam_date, weight_pct, target_score, syllabus_summary)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            e_id, user_id, exam_data.get("subject_id", ""),
            exam_data.get("subject_name") or exam_data.get("subject", "Module"),
            exam_data.get("title", "Midterm / Final Exam"),
            exam_data.get("exam_date") or exam_data.get("date", ""),
            safe_float(exam_data.get("weight_pct") or exam_data.get("weight", 30.0)),
            safe_float(exam_data.get("target_score") or exam_data.get("target", 85.0)),
            exam_data.get("syllabus_summary") or exam_data.get("syllabus", "")
        ))
        return e_id

    def delete_exam(self, user_id: str, exam_id: str):
        cur = self.execute("DELETE FROM exams WHERE id = %s AND user_id = %s", (exam_id, user_id))
        return getattr(cur, "rowcount", 0) == 1

    def get_user_exams(self, user_id: str):
        return self.fetchall("SELECT * FROM exams WHERE user_id = %s ORDER BY exam_date ASC", (user_id,))

    # -------------------------------------------------------------------------
    # GOALS
    # -------------------------------------------------------------------------
    def add_goal(self, user_id: str, goal_data: dict):
        g_id = goal_data.get("id") or f"goal_{uuid.uuid4().hex[:10]}"
        self.execute("""
            INSERT INTO goals (id, user_id, title, category, target_date, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            g_id, user_id, goal_data.get("title", "Academic Goal"),
            goal_data.get("category", "study"),
            goal_data.get("target_date") or goal_data.get("date", ""),
            goal_data.get("status", "active")
        ))
        return g_id

    def delete_goal(self, user_id: str, goal_id: str):
        cur = self.execute("DELETE FROM goals WHERE id = %s AND user_id = %s", (goal_id, user_id))
        return getattr(cur, "rowcount", 0) == 1

    def get_user_goals(self, user_id: str):
        return self.fetchall("SELECT * FROM goals WHERE user_id = %s ORDER BY created_at DESC", (user_id,))

    # -------------------------------------------------------------------------
    # STUDY SESSIONS & TELEMETRY
    # -------------------------------------------------------------------------
    def add_study_session(self, user_id: str, session_data: dict):
        s_id = session_data.get("id") or f"sess_{uuid.uuid4().hex[:10]}"
        self.execute("""
            INSERT INTO study_sessions (id, user_id, subject_name, duration_minutes, focus_score, stamina_start, stamina_end, date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            s_id, user_id, session_data.get("subject_name") or session_data.get("subject", "Coursework"),
            safe_int(session_data.get("duration_minutes") or session_data.get("duration", 45)),
            safe_float(session_data.get("focus_score", 90.0)),
            safe_float(session_data.get("stamina_start", 95.0)),
            safe_float(session_data.get("stamina_end", 80.0)),
            session_data.get("date", "Today")
        ))
        return s_id

    def get_user_study_sessions(self, user_id: str):
        return self.fetchall("SELECT * FROM study_sessions WHERE user_id = %s ORDER BY created_at DESC", (user_id,))

    # -------------------------------------------------------------------------
    # NOTIFICATIONS
    # -------------------------------------------------------------------------
    def add_notification(self, user_id: str, notif_data: dict):
        n_id = notif_data.get("id") or f"notif_{uuid.uuid4().hex[:10]}"
        self.execute("""
            INSERT INTO notifications (id, user_id, title, description, type, is_read)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            n_id, user_id, notif_data.get("title", "Notification"),
            notif_data.get("description", ""),
            notif_data.get("type", "info"),
            1 if notif_data.get("is_read") else 0
        ))
        return n_id

    def get_user_notifications(self, user_id: str):
        return self.fetchall("SELECT * FROM notifications WHERE user_id = %s ORDER BY created_at DESC", (user_id,))


    # -------------------------------------------------------------------------
    # PARENT-STUDENT GOVERNANCE & PERMISSIONS
    # -------------------------------------------------------------------------
    def link_parent_student(self, parent_email: str, student_code_or_email: str, parent_name: str = ""):
        """Create a pending parent-link request; only the student can approve it."""
        p_email = (parent_email or "").strip().lower()
        identifier = (student_code_or_email or "").strip()
        parent = self.get_user_by_email(p_email)
        if not parent or parent.get("role") not in ("parent", "guardian"):
            return None, "A registered parent/guardian account is required."
        student = self.get_user_by_email(identifier) if "@" in identifier else self.get_user_by_linking_code(identifier)
        if not student or student.get("role") not in ("student", "student_adult", "student_minor"):
            return None, "Student not found with this email or linking code."
        if student.get("id") == parent.get("id"):
            return None, "A parent account cannot link to itself."

        existing = self.fetchone(
            "SELECT * FROM parent_student_links WHERE LOWER(parent_email) = LOWER(%s) AND LOWER(student_email) = LOWER(%s)",
            (p_email, student["email"]),
        )
        now = datetime.datetime.now().isoformat()
        if existing:
            link_id = existing["id"]
            if existing.get("status") != "approved":
                self.execute(
                    "UPDATE parent_student_links SET status = 'pending', approved_at = NULL, parent_name = %s, student_name = %s WHERE id = %s",
                    (parent_name or parent.get("name", "Parent"), student.get("name", "Student"), link_id),
                )
            return link_id, None

        link_id = f"link_{uuid.uuid4().hex[:12]}"
        self.execute("""
            INSERT INTO parent_student_links (
                id, parent_id, student_id, parent_email, student_email,
                parent_name, student_name, status, linking_code, approved_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, NULL)
        """, (
            link_id, parent["id"], student["id"], p_email, student["email"].lower(),
            parent_name or parent.get("name", "Parent"), student.get("name", "Student"),
            student.get("linking_code", ""),
        ))
        # Permission row records the guardian request but does not enable access.
        self.execute("UPDATE permissions SET guardian_email = %s, approved = 0 WHERE user_id = %s", (p_email, student["id"]))
        return link_id, None

    def get_parent_links_for_student(self, student_id: str):
        return self.fetchall("SELECT * FROM parent_student_links WHERE student_id = %s", (student_id,))

    def get_linked_students_for_parent(self, parent_email: str):
        return self.fetchall("SELECT * FROM parent_student_links WHERE LOWER(parent_email) = LOWER(%s) AND status = 'approved'", (parent_email.strip(),))

    def update_parent_permissions(self, student_id: str, guardian_email: str, allow_hours: bool, allow_proofs: bool, allow_nudges: bool):
        self.execute("""
            UPDATE permissions
            SET guardian_email = %s, allow_view_study_hours = %s, allow_view_proofs = %s, allow_nudges = %s
            WHERE user_id = %s
        """, (guardian_email.strip().lower(), 1 if allow_hours else 0, 1 if allow_proofs else 0, 1 if allow_nudges else 0, student_id))
        return True

    def approve_parent_link(self, relationship_id: str, student_id: str = None):
        if not relationship_id or not student_id:
            return False
        now_str = datetime.datetime.now().isoformat()
        cur = self.execute(
            "UPDATE parent_student_links SET status = 'approved', approved_at = %s WHERE id = %s AND student_id = %s AND status = 'pending'",
            (now_str, relationship_id, student_id),
        )
        if getattr(cur, "rowcount", 0) != 1:
            return False
        self.execute("UPDATE permissions SET approved = 1 WHERE user_id = %s", (student_id,))
        return True

    def revoke_parent_link(self, relationship_id: str, student_id: str = None):
        if not relationship_id or not student_id:
            return False
        cur = self.execute(
            "UPDATE parent_student_links SET status = 'revoked', approved_at = NULL WHERE id = %s AND student_id = %s AND status IN ('pending', 'approved')",
            (relationship_id, student_id),
        )
        if getattr(cur, "rowcount", 0) != 1:
            return False
        remaining = self.fetchone("SELECT id FROM parent_student_links WHERE student_id = %s AND status = 'approved' LIMIT 1", (student_id,))
        if not remaining:
            self.execute("UPDATE permissions SET approved = 0 WHERE user_id = %s", (student_id,))
        return True

    def get_parent_links(self, student_email: str = None, student_id: str = None, parent_email: str = None):
        if student_email:
            return self.fetchall("SELECT * FROM parent_student_links WHERE LOWER(student_email) = LOWER(%s)", (student_email.strip(),))
        if student_id:
            return self.fetchall("SELECT * FROM parent_student_links WHERE student_id = %s", (student_id,))
        if parent_email:
            return self.fetchall("SELECT * FROM parent_student_links WHERE LOWER(parent_email) = LOWER(%s)", (parent_email.strip(),))
        return self.fetchall("SELECT * FROM parent_student_links")


    # -------------------------------------------------------------------------
    # BEHAVIOR PATTERNS MANAGEMENT
    # -------------------------------------------------------------------------
    def get_behavior_patterns(self, user_id: str):
        rows = self.fetchall("SELECT * FROM behavior_patterns WHERE user_id = %s ORDER BY updated_at DESC", (user_id,))
        for r in rows:
            r["pattern_id"] = r.get("pattern_id") or r.get("id")
            if not r.get("name"):
                r["name"] = r.get("title", "")
        return rows

    def update_behavior_pattern(self, user_id: str, pattern_id: str, data: dict):
        existing = self.fetchone("SELECT * FROM behavior_patterns WHERE (id = %s OR pattern_id = %s) AND user_id = %s", (pattern_id, pattern_id, user_id))
        title = (data.get("title") or data.get("name") or pattern_id).strip()
        ptype = data.get("pattern_type", "productivity")
        conf = safe_float(data.get("confidence"), 85.0)
        weight = safe_float(data.get("weight"), 1.0)
        summary = data.get("evidence_summary") or data.get("description", "")
        is_active = 1 if data.get("is_active", True) else 0

        if not existing:
            new_id = f"bp_{uuid.uuid4().hex[:10]}"
            self.execute("""
                INSERT INTO behavior_patterns (id, user_id, pattern_id, title, pattern_type, confidence, evidence_count, evidence_summary, weight, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s, %s)
            """, (new_id, user_id, pattern_id, title, ptype, conf, summary, weight, is_active))
            return True

        fields = []
        params = []
        if "title" in data or "name" in data:
            fields.append("title = %s")
            params.append(title)
        if "pattern_type" in data:
            fields.append("pattern_type = %s")
            params.append(data["pattern_type"])
        if "confidence" in data:
            fields.append("confidence = %s")
            params.append(safe_float(data["confidence"], 85.0))
        if "weight" in data:
            fields.append("weight = %s")
            params.append(safe_float(data["weight"], 1.0))
        if "evidence_summary" in data or "description" in data:
            fields.append("evidence_summary = %s")
            params.append(summary)
        if "is_active" in data:
            fields.append("is_active = %s")
            params.append(1 if data["is_active"] else 0)
        if not fields:
            return False
        fields.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([existing["id"], user_id])
        sql = f"UPDATE behavior_patterns SET {', '.join(fields)} WHERE id = %s AND user_id = %s"
        self.execute(sql, tuple(params))
        return True

    def delete_behavior_pattern(self, user_id: str, pattern_id: str):
        self.execute("DELETE FROM behavior_patterns WHERE (id = %s OR pattern_id = %s) AND user_id = %s", (pattern_id, pattern_id, user_id))
        return True

    def reset_behavior_patterns(self, user_id: str):
        """Clear learned patterns for this account; never seed fabricated observations."""
        self.execute("DELETE FROM behavior_patterns WHERE user_id = %s", (user_id,))
        return True

    # -------------------------------------------------------------------------
    # PRIVACY SETTINGS
    # -------------------------------------------------------------------------
    def get_privacy_settings(self, user_id: str):
        row = self.fetchone("SELECT * FROM privacy_settings WHERE user_id = %s", (user_id,))
        if not row:
            self.execute("INSERT IGNORE INTO privacy_settings (user_id) VALUES (%s)", (user_id,))
            row = self.fetchone("SELECT * FROM privacy_settings WHERE user_id = %s", (user_id,))
        return row or {
            "academic_calendar": 1,
            "biometric_telemetry": 1,
            "parent_live_nudges": 1,
            "allow_research_benchmarking": 0
        }

    def toggle_privacy_setting(self, user_id: str, setting_key: str, value: bool = None):
        allowed = ["academic_calendar", "biometric_telemetry", "parent_live_nudges", "allow_research_benchmarking"]
        if setting_key not in allowed:
            return False

        cur = self.get_privacy_settings(user_id)
        new_val = (1 if value else 0) if value is not None else (0 if cur.get(setting_key) else 1)
        self.execute(f"UPDATE privacy_settings SET {setting_key} = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s", (new_val, user_id))
        return bool(new_val)

    # -------------------------------------------------------------------------
    # VERSIONED LEGACY APPLICATION STATE (migration bridge)
    # -------------------------------------------------------------------------
    def load_application_state(self, state_key="global"):
        """Return one versioned compatibility document, optionally scoped to a user."""
        row = self.fetchone(
            "SELECT state_json, version FROM application_state WHERE state_key = %s",
            (str(state_key),),
        )
        if not row:
            return None, None
        payload = row.get("state_json")
        try:
            state = json.loads(payload) if isinstance(payload, str) else payload
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Persisted TwinStudy application state is invalid JSON") from exc
        if not isinstance(state, dict):
            raise RuntimeError("Persisted TwinStudy application state must be a JSON object")
        return state, int(row.get("version") or 1)

    def initialize_application_state(self, state, state_key="global"):
        """Initialize one state document without overwriting an existing document."""
        key = str(state_key)
        if len(key) > 64:
            raise ValueError("Application state key exceeds database schema limit")
        payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        self.execute(
            "INSERT IGNORE INTO application_state (state_key, state_json, version) VALUES (%s, %s, 1)",
            (key, payload),
        )
        return self.load_application_state(key)

    def save_application_state(self, state, expected_version, state_key="global"):
        """Compare-and-swap one state document; reject stale concurrent writes."""
        key = str(state_key)
        if len(key) > 64:
            raise ValueError("Application state key exceeds database schema limit")
        payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        cur = self.execute(
            "UPDATE application_state SET state_json = %s, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE state_key = %s AND version = %s",
            (payload, key, int(expected_version)),
        )
        if getattr(cur, "rowcount", 0) != 1:
            raise RuntimeError("TwinStudy state changed concurrently; reload before saving to prevent lost updates")
        return int(expected_version) + 1

    # -------------------------------------------------------------------------
    # SERVERLESS-SAFE OTP STORAGE
    # -------------------------------------------------------------------------
    def save_otp(self, email: str, code: str, purpose: str, data: dict = None, expires_minutes: int = 10):
        email_clean = str(email or "").strip().lower()
        if not email_clean or len(email_clean) > 191:
            raise ValueError("A valid email address is required for OTP storage")
        code_value = str(code or "").strip()
        if len(code_value) != 64 or any(c not in "0123456789abcdef" for c in code_value.lower()):
            raise ValueError("Only a SHA-256 OTP digest may be persisted")
        exp = datetime.datetime.now() + datetime.timedelta(minutes=max(1, min(30, safe_int(expires_minutes, 10))))
        exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
        data = data or {}
        data_json = json.dumps(data, ensure_ascii=False)
        attempts_left = max(0, min(5, safe_int(data.get("attempts_left"), 5)))
        if self.engine_type == "mysql":
            sql = """INSERT INTO verification_otps (email,code,purpose,data,attempts_left,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE code=VALUES(code),
                purpose=VALUES(purpose),data=VALUES(data),attempts_left=VALUES(attempts_left),expires_at=VALUES(expires_at)"""
        else:
            sql = """INSERT INTO verification_otps (email,code,purpose,data,attempts_left,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(email) DO UPDATE SET code=excluded.code,
                purpose=excluded.purpose,data=excluded.data,attempts_left=excluded.attempts_left,expires_at=excluded.expires_at"""
        self.execute(sql, (email_clean, code_value, str(purpose or "")[:64], data_json, attempts_left, exp_str))
        return True

    def get_otp(self, email: str):
        row = self.fetchone("SELECT * FROM verification_otps WHERE LOWER(email) = LOWER(%s)", (email.strip(),))
        if not row:
            return None
        # Invalidate records written by older releases, which stored raw OTP codes
        # and sometimes plaintext registration payloads. Users can request a new code.
        stored_code = str(row.get("code") or "")
        if len(stored_code) != 64 or any(c not in "0123456789abcdef" for c in stored_code.lower()):
            self.delete_otp(email, stored_code, row.get("purpose"))
            return None
        # Fail closed if expiry is missing, malformed, or already elapsed.
        try:
            exp_value = row.get("expires_at")
            if isinstance(exp_value, datetime.datetime):
                exp = exp_value
            else:
                exp = datetime.datetime.strptime(str(exp_value), "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() >= exp:
                self.delete_otp(email, stored_code, row.get("purpose"))
                return None
        except (TypeError, ValueError):
            self.delete_otp(email, stored_code, row.get("purpose"))
            return None
        return row

    def decrement_otp_attempts(self, email: str, code_digest: str = None, purpose: str = None):
        """Atomically consume an OTP attempt and return the remaining count."""
        email_clean = str(email or "").strip().lower()
        conditions = "LOWER(email) = LOWER(%s) AND attempts_left > 0"
        params = [email_clean]
        if code_digest is not None:
            conditions += " AND code = %s"
            params.append(str(code_digest))
        if purpose is not None:
            conditions += " AND purpose = %s"
            params.append(str(purpose))
        self.execute(
            "UPDATE verification_otps SET attempts_left = CASE WHEN attempts_left > 0 THEN attempts_left - 1 ELSE 0 END "
            "WHERE " + conditions,
            tuple(params),
        )
        select_conditions = "LOWER(email) = LOWER(%s)"
        select_params = [email_clean]
        if code_digest is not None:
            select_conditions += " AND code = %s"
            select_params.append(str(code_digest))
        if purpose is not None:
            select_conditions += " AND purpose = %s"
            select_params.append(str(purpose))
        row = self.fetchone("SELECT attempts_left FROM verification_otps WHERE " + select_conditions, tuple(select_params))
        return int(row.get("attempts_left", 0)) if row else 0

    def consume_otp(self, email: str, purpose: str, code_digest: str):
        """Atomically validate and consume one unexpired OTP across workers."""
        email_clean = str(email or "").strip().lower()
        conn = self.get_connection()
        try:
            if self.engine_type == "mysql":
                conn.begin()
            else:
                conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            suffix = " FOR UPDATE" if self.engine_type == "mysql" else ""
            cur.execute(self._translate_query(
                "SELECT * FROM verification_otps WHERE LOWER(email) = LOWER(%s)" + suffix
            ), (email_clean,))
            row = cur.fetchone()
            record = dict(row) if row and not isinstance(row, dict) else row
            if not record:
                conn.rollback()
                return None

            stored_digest = str(record.get("code") or "")
            try:
                expires = record.get("expires_at")
                if not isinstance(expires, datetime.datetime):
                    expires = datetime.datetime.fromisoformat(str(expires))
            except (TypeError, ValueError):
                expires = None
            valid = (
                record.get("purpose") == purpose
                and int(record.get("attempts_left") or 0) > 0
                and expires is not None
                and datetime.datetime.now() < expires
                and secrets.compare_digest(stored_digest, str(code_digest or ""))
            )
            if not valid:
                conn.rollback()
                return None

            cur.execute(self._translate_query(
                "DELETE FROM verification_otps WHERE LOWER(email) = LOWER(%s)"
            ), (email_clean,))
            payload = record.get("data") or "{}"
            data = json.loads(payload) if isinstance(payload, str) else dict(payload)
            conn.commit()
            data.update({
                "purpose": record.get("purpose"), "code": stored_digest,
                "_code_is_hash": True, "attempts_left": int(record.get("attempts_left", 0)),
                "expires_at": expires.isoformat(),
            })
            return data
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def delete_otp(self, email: str, code_digest: str = None, purpose: str = None):
        conditions = "LOWER(email) = LOWER(%s)"
        params = [str(email or "").strip()]
        if code_digest is not None:
            conditions += " AND code = %s"
            params.append(str(code_digest))
        if purpose is not None:
            conditions += " AND purpose = %s"
            params.append(str(purpose))
        self.execute("DELETE FROM verification_otps WHERE " + conditions, tuple(params))

    # -------------------------------------------------------------------------
    # CHAT STORAGE
    # -------------------------------------------------------------------------
    def get_or_create_conversation(self, user_id: str, conv_id: str = None):
        if conv_id:
            conv = self.fetchone("SELECT * FROM chat_conversations WHERE id = %s AND user_id = %s", (conv_id, user_id))
            if conv:
                return conv["id"]

        latest = self.fetchone("SELECT id FROM chat_conversations WHERE user_id = %s ORDER BY updated_at DESC LIMIT 1", (user_id,))
        if latest:
            return latest["id"]

        new_id = f"conv_{uuid.uuid4().hex[:12]}"
        self.execute("""
            INSERT INTO chat_conversations (id, user_id, title)
            VALUES (%s, %s, %s)
        """, (new_id, user_id, "Study Buddy Consultation"))
        return new_id

    def add_chat_message(self, conversation_id: str, user_id: str, role: str, content: str, context_used: str = None):
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        self.execute("""
            INSERT INTO chat_messages (id, conversation_id, user_id, role, content, context_used)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (msg_id, conversation_id, user_id, role, content, context_used))
        self.execute("UPDATE chat_conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = %s", (conversation_id,))
        return msg_id

    def get_recent_chat_messages(self, conversation_id: str, limit: int = 10):
        messages = self.fetchall("""
            SELECT role, content, created_at FROM chat_messages
            WHERE conversation_id = %s
            ORDER BY created_at DESC, id DESC LIMIT %s
        """, (conversation_id, limit))
        messages.reverse()
        return messages

    # -------------------------------------------------------------------------
    # DECISIONS & FEEDBACK
    # -------------------------------------------------------------------------
    def record_decision(self, user_id: str, question: str, baseline_data: dict, simulation_result: dict, recommended_option: str):
        dec_id = f"dec_{uuid.uuid4().hex[:12]}"
        self.execute("""
            INSERT INTO decisions (id, user_id, question, baseline_data, simulation_result, recommended_option)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            dec_id, user_id, question,
            json.dumps(baseline_data),
            json.dumps(simulation_result),
            recommended_option
        ))
        return dec_id

    def update_decision_feedback(self, decision_id: str, user_id: str, agreement: str, chosen_option: str, user_reason: str):
        self.execute("""
            UPDATE decisions
            SET agreement = %s, chosen_option = %s, user_reason = %s
            WHERE id = %s AND user_id = %s
        """, (agreement, chosen_option, user_reason, decision_id, user_id))

        patterns = self.fetchall("SELECT * FROM behavior_patterns WHERE user_id = %s", (user_id,))
        for p in patterns:
            ev_count = p.get("evidence_count", 1) + 1
            cur_weight = p.get("weight", 1.0)
            if agreement == "agree":
                new_weight = min(2.0, cur_weight + 0.05)
                new_conf = min(98.0, p.get("confidence", 85.0) + 0.8)
            else:
                new_weight = max(0.5, cur_weight - 0.05)
                new_conf = max(60.0, p.get("confidence", 85.0) - 1.2)

            self.execute("""
                UPDATE behavior_patterns
                SET evidence_count = %s, weight = %s, confidence = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (ev_count, round(new_weight, 2), round(new_conf, 1), p["id"]))

        return True


def random_digits(n=4):
    import random
    return "".join(str(random.randint(0, 9)) for _ in range(n))


# Global singleton instance
db_mgr = DatabaseManager()
