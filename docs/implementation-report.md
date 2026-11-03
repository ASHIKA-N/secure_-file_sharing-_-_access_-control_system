# Advanced feature implementation report

The advanced-feature specification was integrated into the existing Oracle 21c application. The original stack, accounts, encrypted files, JSP/Faces split, and one-command launcher were retained.

| Delivered area | Implementation |
|---|---|
| Recipient policies | Independent view/download permissions and counts, presets, confirmation, expiry, hours, OTP and version targets |
| Access requests | Opt-in authenticated catalogue, duplicate-pending prevention, owner approval through policy confirmation, rejection/cancellation history |
| Central decisions | PermissionEngine checks active actors/owners/versions, grant ancestry, actions, UTC expiry, named-zone windows and allowances |
| Counted transfers | Verified content prepared before atomic consumption; ancestors share budgets; Range requests rejected |
| Viewing | Ten-minute recipient/version/grant-bound sessions, duplicate initiation reuse, refresh reuse, close/expiry and per-resource rechecks |
| Rendered content | Server PNG rendering for PDF/TXT/PNG/JPEG; visible identity/time overlays and bounded PDF subprocesses |
| Delegation | Owner-authorized onward sharing, no cycles/ancestor invitations, three levels, constrained expiry/actions/pins and branch revocation |
| OTP | SecureRandom codes, independent HMAC verifiers, five-minute TTL, attempt/resend limits, single-use two-minute operation permits; SMTP and explicit LOCAL mailbox |
| PDF derivatives | Personalized per-transfer watermarks on every page, unchanged encrypted originals, no permanent plaintext derivatives |
| Alerts | Four configurable persistent-event rules, cooldown deduplication, administrator review and owner-scoped privacy |
| Audit evidence | Serialized canonical hash chain, administrator verification, independent HMAC checkpoints and periodic exports |
| File versions | Logical file plus immutable encrypted versions, history, new-version upload, archive, latest/pinned grants and preserved counts |
| User/admin interfaces | Requests, policy preview/management, viewer, OTP, versions, notifications, owner alerts; Faces alert review and audit/checkpoint pages |
| Persistence | Additive V002 Oracle migration, indexes/constraints/FKs, DTOs, optimistic versions and short locking transactions |
| Documentation | Updated README, architecture/ER diagram, advanced feature notes, configuration examples, demo and actual verification results |

## Actual verification

The final `mvn clean verify` completed successfully: 47 tests passed with zero failures, errors or skipped tests. The expanded automated suite and Oracle-backed web checks are recorded in test-cases.md. Live Oracle checks passed the complete confidential-PDF request/approval/OTP/view-once flow, counted personalized PDF downloads, three-level shared-budget delegation, version pinning/archiving, alerts, Faces acknowledgement and protected audit verification/checkpoint export.

Before V002, original file/grant/audit metadata was preserved in dedicated backup tables. Post-migration checks found zero missing original files/grants and zero altered original audit fields. Both original file rows received preserved version records using their existing storage IDs/wrapped keys. The original master key and database password were confirmed unchanged without printing them. Existing accounts were retained. Clearly labelled live-test accounts/audit records remain; temporary test files were deleted through the application.

The web audit verification test exposed timestamp precision differences between Java instants and persisted timestamps; audit instants are now normalized to microseconds before hashing. A lingering Windows JVM blocked one clean build, so a clean stop script was added and tested. These checks prevented reporting only service-level success while leaving the web flow unverified.

## Run and limits

Run: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`  
Open: http://localhost:8080/securefiles/login  
Stop: `powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1`

Real external SMTP delivery and manual visual/accessibility/HTTPS checks were not performed. LOCAL OTP mode never claims to send email. Screenshots, browser capture and forwarding downloaded copies remain possible. PDF limits, signature/encryption restrictions, font coverage, no range/resume, shared budgets and the audit/server trust boundary are documented in advanced-features.md. No counter reset, machine-learning abuse claim, DRM guarantee or security certification is provided.

The earlier implementation history below is retained for review; the advanced section and current source take precedence over historical MySQL/download-only descriptions.

---

# Oracle 21c update

At the user's request the database target changed from MySQL to Oracle Database 21c XE 21.3.0.0.0. The JDBC driver is now ojdbc11 21.21.0.0. The SQL migration uses Oracle identity columns, NUMBER booleans/IDs, RAW encryption metadata, VARCHAR2 text and timezone-aware timestamps. Descriptions are nullable because Oracle treats empty strings as NULL; DTOs display them as empty text. Queries handle blank search parameters consistently.

`scripts/run.ps1` provides a one-command Windows launch with embedded Tomcat, explicit schema initialization, generated credentials protected using Windows DPAPI, and saved master-key reuse. It creates only a dedicated app account and preserves existing accounts/tables. Production startup continues to use Hibernate schema validation.

The user explicitly approved Oracle setup and live testing after the initial automatic approval rejection. Setup created the dedicated SECUREFILES_APP schema in XEPDB1 and applied V001. Oracle identity columns required CREATE SEQUENCE; the missing grant was added and initialization safely resumed from the empty schema-version table. Hibernate production schema validation passed on Oracle 21.3.0.0.0.

Live HTTP checks on Oracle-backed Tomcat passed registration/login for three users, multipart encrypted upload, blank descriptions/searches, owner and recipient downloads, unrelated-user denial, recipient re-share denial, CSRF rejection, revocation, activity, deletion, admin Faces user/audit rendering and actual AJAX account disabling with existing-session rejection. The verification file was deleted through the application; clearly named verification account/audit records remain. An explicit local bootstrap created a verification admin with a generated password, protected using Windows DPAPI in ignored .tools/live-test.xml. No default credentials were committed. Evidence: .tools/oracle-live-results.log and .tools/oracle-server.log. The temporary verification server used port 8081 and was stopped after testing. The normal launcher defaults to port 8080.

The original implementation history below describes the earlier MySQL target; the current code, schema and README target Oracle. Historical unverified-MySQL notes do not apply to the now-completed Oracle checks.

---

# Implementation report

Project: **Secure File Sharing and Access Control System**  
Prepared: **2 November 2026**

## Work completed

The original project folder contained only Git metadata. The supplied prompt was used as the application specification. Existing files were preserved. The application, database script, tests and documentation were created in the current project directory.

| Work | What was implemented |
|---|---|
| Maven project | Java 17 WAR with exact dependency versions and compatible Jakarta APIs |
| Accounts | Registration, normalized unique emails, USER-only public registration, Argon2id passwords and explicit local admin bootstrap |
| Login and sessions | Generic login failures, bounded failed-login throttle, session-ID rotation, 20-minute idle timeout, POST logout and active-account rechecks |
| User pages | Login, registration, dashboard, upload, My Files, file details/sharing, Shared with Me, activity and friendly errors using protected JSP views |
| Private uploads | 10 MiB limit, configurable default 100 MiB quota, owner-row locking, simple safe filenames, Tika detection and format checks |
| Encryption | AES-256-GCM with a fresh per-file key and IV; separate authenticated master-key wrapping and file/version AAD |
| Storage | Encrypted files outside the WAR; random storage names, owner-only storage permissions, encrypted temporary writes and failure cleanup |
| Downloads | Service permission checks, full GCM verification before plaintext response, final access recheck, attachment headers and no-store caching |
| Sharing | Exact active-recipient email, optional UTC expiry, DOWNLOAD-only grants, revocation and unique file/recipient pair |
| File management | Description editing and tombstone deletion; deletion revokes grants and physical cleanup is retryable |
| Admin pages | Faces 4 Facelets with CDI user search/pagination, activate/disable actions and read-only audit filters |
| Persistence | One SessionFactory, pooled connections, short explicit transactions, DTOs, foreign keys, indexes and optimistic versions |
| Audit | Login results, uploads, download decisions, shares, revocation, edits, deletion and account status; retained metadata after disabling/deletion |
| Web controls | Synchronizer CSRF protection for JSP, Faces postbacks and AJAX; security headers, output escaping, cookie settings and no public sharing routes |
| Presentation | Local CSS/JavaScript, light background, dark blue navigation, readable tables, empty states, confirmation and focus styling |
| Documentation | Windows setup, schema migration, configuration examples, architecture, Mermaid relationships, three-user demo and verification record |

## Dependency choices

The application uses Servlet 6.0.0 as provided by Tomcat, JSP 3.1 from Tomcat, Jakarta Tags API 3.0.2 / implementation 3.0.1, Mojarra 4.0.28, Weld Servlet 5.1.7.Final, Hibernate ORM 6.6.59.Final, MySQL Connector/J 8.4.0, HikariCP 5.1.0, Argon2 JVM 2.12 and Tika Core 3.3.3. The integration container is Tomcat 10.1.61. Versions are pinned in `pom.xml`.

Tomcat's compatibility table, the Mojarra **4.0 branch**, Weld 5.1 documentation, Hibernate 6.6 documentation and OWASP guidance were consulted. Maven Central metadata confirmed patch availability within the required lines. Faces 4.1/Weld 6 were deliberately avoided because the requested application targets the Jakarta EE 10 / Tomcat 10.1 generation. The README contains source links and credits. No third-party visual assets or project branding were copied.

## How the implementation works

`UserController` handles HTTP and chooses JSP views. `AdminBean` adapts Faces actions. Both call `AppService`, which enforces account, ownership, grant and expiry rules inside short `Database` transactions. `SecurityFilter` provides an additional outer check. Admin privileges authorize metadata operations, not another user's private download. UI data is copied to DTO maps before the transaction closes; views do not open Hibernate sessions.

`Crypto` wraps random data keys using the environment master key and binds both encryption layers to the file ID/version. The storage layer receives ciphertext only. Database metadata and disk bytes cannot commit atomically, so cleanup is explicit: failed uploads check committed metadata, old orphans are swept, and deleted files remain tombstoned while disk removal is retried. The architecture document explains these decisions and the important classes for review questions.

## Verification performed

`mvn clean verify` completed successfully and produced **`target/securefiles.war`**. All **21 tests passed**: 6 focused unit tests, 10 persistence/service integration tests and 5 Tomcat HTTP integration tests. There were zero failures, errors or skipped tests. The Tomcat tests exercised JSP registration/login, multipart upload/download, Faces rendering, Faces AJAX account disabling, session invalidation, CSRF rejection and download authorization. See `test-cases.md` for the detailed expected/actual distinction and generated report locations.

The first checks exposed a test compilation ambiguity, lazy-proxy field access, incomplete embedded-container dependencies and incomplete simulated Faces AJAX event parameters. These were corrected before the final clean build. Java source was formatted for readability.

## Remaining verification and limits

MySQL and standalone Tomcat deployment with real environment secrets were not run because a configured MySQL installation was unavailable. The delivered MySQL migration and production schema validation must be exercised during local setup. Embedded Tomcat tests use isolated H2 schemas, whose SQL and concurrency behavior cannot fully establish MySQL compatibility. Browser visual/accessibility checks and HTTPS transport were not performed. These are recorded as unverified checks, not successful results.

The application does not scan for malware, provide public links or recall downloaded copies. Encryption is server-side, not end-to-end. The master key must be backed up separately and cannot be silently replaced for existing files. Local throttling is process-bound. Audit rows are not tamper-proof. Administrator accounts are protected from disabling through the UI to avoid lockout. Content validation is intentionally bounded and is not a complete PDF security analysis. No independent security audit is claimed.

## Files to review and run

- `README.md`: exact Windows prerequisites, MySQL creation/grants, environment setup, build, admin bootstrap and deployment commands.
- `database/V001__initial_schema.sql`: versioned MySQL schema.
- `.env.example` and `scripts/configure.ps1`: configuration names and interactive secret setup.
- `docs/architecture.md`: MVC, class responsibilities, request flow, cryptography, cleanup and ER diagram.
- `docs/demo-guide.md`: demonstration with Anu, Bala, Chitra and admin.
- `docs/test-cases.md`: test expectations, actual results and checks not run.
- `target/securefiles.war`: generated deployable artifact.
