# TwinStudy — Product Requirements Document

## 1. Purpose

TwinStudy is intended to provide students with a web-based place to access academic productivity features and AI-assisted study support, with separate experiences for students, parents, and other authorized college roles as the product evolves.

This document describes the release candidate's intended scope. It does not claim every listed capability is complete or production-ready.

## 2. User roles

- **Student:** accesses their own academic productivity information and study tools after authentication.
- **Parent:** accesses a linked student's permitted information only after parent authentication and student approval of the relationship.
- **Teacher and administrator:** planned/target roles for college LMS information and content management; availability must be verified in the current implementation before being treated as complete.

## 3. Functional requirements

### Authentication and account verification
- Support account registration and verification workflows.
- Persist verification OTP digests in the relational database.
- Reject expired/malformed OTP records and decrement incorrect-code attempts atomically.
- Do not return clear OTP values in API responses.
- Invalidate a pending OTP if email delivery fails.
- Support configured Google Identity Services sign-in where valid provider credentials are supplied.

### Student data isolation
- Require an authenticated student session for student-only operations.
- Scope task and academic reads/writes to the signed-in user.
- Do not accept a client-supplied email as proof of identity or ownership.
- Verify ownership before accepting proof, feedback, or simulator-related actions.

### Parent access
- Require parent authentication.
- Keep newly requested parent/student links pending until the student approves.
- Limit parent views to approved relationships and permitted information.

### Study productivity and AI support
- Provide the frontend and AI service integration present in the release.
- Ensure AI features use the authenticated student's authorized context only.
- Validate the natural-language simulator and Study Buddy against real user-scoped academic records before production.

## 4. Non-functional requirements

- **Security:** least privilege, server-side authorization, no secrets in source control, no clear OTP storage.
- **Durability:** production academic state must use durable shared storage rather than ephemeral instance files.
- **Privacy:** students must not be able to access another student's records by changing request parameters.
- **Reliability:** email failures, database errors, invalid sessions, and expired OTPs should fail safely.
- **Maintainability:** release checks and integration tests should be repeatable.

## 5. Acceptance criteria

- Static release checks and Python compilation pass.
- OTP digests persist in MariaDB and temporary OTP rows can be cleaned up.
- Incorrect OTPs are rejected and attempt counters decrease.
- Registration and authentication integration tests cover success, failure, expiry, resend, and concurrency.
- Student and parent route authorization is verified with multiple test identities.
- No production deployment is approved until remaining JSON-backed state is migrated and verified.

## 6. Known gaps

The v6 release notes identify legacy JSON-backed application state and incomplete end-to-end coverage as blockers. This PRD does not mark those items as complete.
