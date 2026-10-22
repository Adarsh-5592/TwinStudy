# Compatibility-state inventory and migration gate

This is a source-code inventory only. The local ignored database was not opened or
changed while preparing it. No `twin_database.json` source file is present in this
checkout, so record ownership and actual data shape cannot be confirmed here.

## Current storage paths

- In production, `server.py` stores versioned compatibility documents in the
  relational `application_state` table, keyed as `user:<database user id>` after
  authentication. Unauthenticated registration flows use the `global` document.
- In local development, `server.py` reads/writes `twin_database.json` (or `/tmp`
  when the source directory is not writable).
- `db_manager.py` already has normalized tables for account/profile, subjects,
  classes, tasks, grades, exams, goals, study sessions, behavior patterns,
  decisions/feedback, parent links/permissions, privacy settings, calendar,
  notifications, chat, and OTPs.
- Several routes dual-write to normalized tables and compatibility documents.
  Reads do not consistently treat normalized empty collections as authoritative.
- The former `migrate_from_json_if_needed()` importer was not called at startup,
  but its body lacked a dry run, backup, and duplicate/conflict handling. It now
  fails closed before reading a source or connecting for migration. No safe
  migration runner is currently implemented.
- SMTP credential configuration and test-email routes are application-operator
  functions; they must not be exposed to ordinary student or parent sessions.
- All API endpoints are assigned an explicit role category. Newly added endpoints
  default to denied until that category is deliberately assigned.
- Parent dashboard summaries, insight counts, and consistency heatmaps must honor
  the corresponding student choices; consistency may reveal study/rest days but
  must not reveal hours when study-time sharing is off.

## Field mapping and disposition

| Compatibility fields | Existing normalized destination | Migration handling required |
| --- | --- | --- |
| `user`, `registered_users` | `users`, `student_profiles` | Match only by immutable database user ID or verified email; never import password/OTP material from a JSON mirror. Preserve unknown profile fields in an archive until reviewed. |
| `subjects`, `classes`, `tasks` | Corresponding user-scoped tables | Validate ownership and IDs; preserve every record and collision-remap IDs with a recorded mapping. |
| `grades`, `exams`, `subject_targets`, `calendar_events`, `calendar_exams` | `grades`, `exams`, `subjects.target_grade`, academic calendar tables | Preserve existing rows; import missing records idempotently. Do not interpret an empty compatibility list as a delete instruction. Calendar entries may be nested under `registered_users`. |
| `notifications` | `notifications` | Import missing IDs; retain read state and ordering where available. |
| `behavior_patterns` | `behavior_patterns` | Import missing records per verified owner; retain inactive records as well as active ones. |
| `decisions` | `decisions`, `feedback` | Validate owner and decision IDs; preserve outcome and feedback fields. |
| `student_parent_relationships`, `parent_permissions` | `parent_student_links`, `permissions` | Resolve both accounts and relationship approval state; never auto-approve a link during migration. Legacy permission keys need an explicit mapping. |
| telemetry history / activity logs | `study_sessions` (partial), no direct activity-log table | Define lossless field mapping and decide retention before migration; keep original payload archived. |
| `privacy_controls` | `privacy_settings` (partial) | Map only semantically equivalent settings. Keys without an equivalent column (for example GPS/chat toggles) must remain preserved until a destination exists. |
| `twin_status`, `cognitive_weights`, `scoreboard` | No complete normalized destination identified | Keep in compatibility state or archive; do not drop or silently coerce. |
| `pending_verifications` | `verification_otps` | Treat as sensitive transient data. Do not migrate clear OTPs; invalidate expired/pending legacy verification only under an approved account-recovery process. |
| Any unknown top-level or nested fields | None known | Preserve byte-for-byte in a versioned archive and fail closed if the migration cannot account for a field. |

The compatibility schema also has defaults that may not occur in real legacy
documents. A real migration must discover fields from a protected source copy and
must not infer that defaults represent a student's saved data.

## Required migration properties before production cutover

1. Take a provider-native consistent backup of the destination and a read-only copy
   of every source JSON document. Record cryptographic hashes and never print data.
2. Run a dry-run against an isolated copy. Resolve every source record to one
   database owner; ambiguous shared root data must stop for manual resolution.
3. Apply inserts/upserts only for records proven absent. Never delete destination
   records, replace collections, reset sequence state, or overwrite a conflicting
   record. Record ID remaps and per-owner counts in a protected report.
4. Run the same migration twice and show that the second pass changes zero records.
   Compare source, migrated, skipped, and conflict counts and validate ownership.
5. Restore the destination backup into another isolated database and verify the
   restore using counts and hashes. Keep the source archive until sign-off.
6. Only after these checks, separately change reads/writes and verify dual-read
   parity. No production cutover is authorized by this inventory.

## Current blockers

- No legacy JSON source is present in this checkout; the ignored local SQLite file
  is intentionally not inspected or modified.
- Legacy records can be duplicated between top-level arrays and per-user mirrors,
  and some shared root collections have ambiguous ownership.
- `privacy_controls`, telemetry/activity history, twin/scoreboard state, and
  unknown custom fields lack complete normalized destinations.
- Production database credentials and a staging copy are unavailable in this
  workspace. Therefore no migration runner or restore claim is safe to validate
  against the current data.
