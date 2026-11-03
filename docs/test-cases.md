# Current advanced-feature verification

The final advanced build ran `mvn clean verify` successfully with **47 tests passed, zero failures, zero errors and zero skipped**. This supersedes the historical 21-test base-application results below.

| Class | Tests | Result |
|---|---:|---|
| CryptoTest | 6 | Passed |
| AccessPolicyTest | 2 | Passed |
| DocumentRendererTest | 2 | Passed |
| ServiceIT | 10 | Passed |
| AdvancedIT | 20 | Passed |
| WebIT | 7 | Passed |

The focused checks include exact expiry and daily/overnight/DST boundaries; disabled/exhausted downloads; concurrent final transfers and view reservations; refresh, duplicate initiation, closure and expiry; viewer revocation; shared ancestor budgets, cycle/depth/expiry/version restrictions; catalogue privacy and request transitions; OTP wrong attempts, cooldown, expiry, binding, replay and delivery failure; personalized PDF identity on every page, original preservation, unsupported signed/encrypted/malformed PDFs and small-image viewer watermarks; version pinning/counter preservation; alert thresholds/deduplication/privacy; concurrent audit appends and alteration/reordering/truncation/checkpoint-tampering detection. Web tests exercise actual JSP policy confirmation, OTP/viewer/request routes, Faces audit verification and missing/invalid CSRF protections.

Generated evidence: `target/surefire-reports`, `target/failsafe-reports` and ignored `.tools/advanced-final-verify.log`. The isolated database is H2 in Oracle compatibility mode, not a replacement for Oracle verification.

## Actual Oracle 21.3 web verification

The V002 migration was applied to the previously approved local SECUREFILES_APP schema after preserving original metadata. Hibernate production validation passed on the configured Oracle server. Actual HTTP requests to Tomcat completed these workflows successfully:

1. A listed confidential PDF received a request, followed by owner approval through the exact policy confirmation form.
2. The recipient verified an OTP through the explicitly labelled local development mailbox and opened a watermarked PDF viewer. Refresh reused the viewing session. Download and resharing were denied. Closing the session exhausted its one permitted view.
3. A separate PDF had a counted, personalized download; increasing its limit preserved consumption. The next authorized download succeeded and further attempts were denied.
4. Three-level delegation shared the ancestor transfer budget. A new content version did not reset it. Existing viewers stayed pinned, archiving blocked their resources, and parent revocation blocked descendants.
5. Repeated denied requests generated distinct-ID and resharing alerts. Faces acknowledgement, owner-scoped privacy, audit-chain verification and protected checkpoint export succeeded. Administrator role did not grant private-content access.

Result: **ADVANCED ORACLE WEB CHECKS PASSED**, exit code 0. Evidence: ignored `.tools/advanced-oracle-results.log` and `.tools/advanced-oracle-server.log`. Test files were deleted through the application; clearly labelled verification accounts and audit records remain.

Post-migration checks found **0 missing original files**, **0 missing original grants**, **0 changed original audit fields**, and preserved both original content-version/storage/key bindings. The original encryption master key and database password were confirmed unchanged without printing secrets. The finished launcher was restarted against the persisted schema; the clean stop command is included to release Windows WAR file locks before rebuilding.

## Remaining unverified checks and limits

Actual external SMTP delivery was not attempted because no provider credentials/verified sender were supplied. LOCAL mode does not send email. A simulated delivery failure was tested, but that is not evidence of real SMTP success. Manual browser appearance/accessibility review, HTTPS transport and independent security assessment were not performed. PDF/font/rendering limits and copying/audit trust boundaries are documented in advanced-features.md.

## Historical base implementation results

The earlier notes below document previous milestones. Their MySQL/download-only limits and 21-test counts are historical; current setup and feature behavior are described above and in the README.

---

# Oracle update verification

The current application targets Oracle Database 21c XE 21.3.0.0.0 using ojdbc11 21.21.0.0. After explicit user approval, first-time setup created the dedicated SECUREFILES_APP schema in XEPDB1, applied the Oracle migration and passed Hibernate schema validation. The initial missing CREATE SEQUENCE privilege was corrected. No existing user accounts or tables were removed.

Actual Oracle-backed HTTP checks completed successfully on 2 November 2026:

- Three-user registration and login with real Oracle identity IDs.
- Empty descriptions and blank searches, encrypted multipart upload and owner download.
- Exact-email sharing, recipient download, unrelated-user denial and recipient re-share denial.
- Missing CSRF rejection, revocation, activity rendering, deletion and subsequent download denial.
- Explicit administrator bootstrap, Faces users/audit rendering, invalid CSRF rejection and no private-file override.
- Actual Faces AJAX account disabling and rejection of that user's existing session.

Result: LIVE ORACLE HTTP CHECKS PASSED, exit code 0. Evidence is in ignored .tools/oracle-live-results.log and .tools/oracle-server.log. These live checks are separate from the 21 automated JUnit tests. Browser visual review and HTTPS transport remain untested. The verification file was tombstoned/deleted; verification account and audit records remain. The temporary server on port 8081 was stopped after the checks.

The Oracle-target `clean verify` run on 2 November 2026 reported BUILD SUCCESS: 21 tests passed, with zero failures, errors or skipped tests. The isolated tests now use H2 Oracle compatibility mode, including empty-string-as-NULL behavior. This remains H2, not an Oracle server. See the generated Maven reports and `.tools/oracle-verify.log`. Historical results and expected cases from the initial implementation follow; the earlier MySQL deployment notes are historical, not the current setup instructions.

---

# Verification

## Expected outcomes

| Area | Test | Expected result |
|---|---|---|
| Accounts | Register, normalize email and sign in | USER account; case/outer whitespace in email normalized; valid password accepted |
| Accounts | Invalid password, duplicate email, disabled account | Generic invalid login; duplicate rejected; disabled account rejected |
| Throttle | Five failures then retry; advance clock five minutes | Further attempt throttled; attempt after window allowed |
| Routing | Unauthenticated download and direct admin Facelets | Redirect to login, no file bytes or admin data |
| Routing | Expired Faces AJAX session | XML partial-response redirect to login |
| Authorization | Owner and active recipient download | Exact original bytes returned |
| Authorization | Unrelated user changes file ID; administrator tries private file | Consistent unavailable response |
| Expiry | One second before expiry and exactly at expiry | Allowed before; denied at equality |
| Revocation | Owner revokes recipient | Next authorization/download denied |
| Disabled owner | Recipient downloads owner's file | Denied; share disappears from list |
| Grant management | Recipient tries share, revoke, delete or edit | Denied in service layer |
| Grants | Self-sharing and repeat sharing | Self-sharing rejected; one file/recipient row retained |
| CSRF | Missing/invalid token on JSP POST | HTTP 403, no mutation |
| CSRF | Missing/invalid token on Faces full postback and AJAX | HTTP 403, no mutation independently of view state |
| Faces | Valid AJAX account-status action | Account disabled; existing session fails next request |
| Upload | Valid UTF-8 TXT, PNG, JPEG and bounded PDF | Validated and accepted |
| Upload | Traversal, double extension, malformed content, empty or oversized file | Rejected |
| Quota | Two concurrent uploads whose combined size exceeds quota | Only one succeeds |
| Encryption | Fresh keys and IVs; round trip | Original plaintext recovered; repeated encryptions differ |
| Encryption | Wrong master key, changed ciphertext or AAD/file ID | Authentication failure; no plaintext returned |
| Storage | Disk write fails after encrypted file is created | Transaction rolls back; orphan removed |
| Deletion | Physical removal fails after tombstone | Access denied immediately; later cleanup retries successfully |
| Persistence | Unique email and grant pair, DTO boundaries | Constraint enforced; secret fields absent from view DTOs |
| HTTP | JSP registration, login, multipart upload, details, lists, activity and download | Real pages compile on Tomcat; forms work; downloaded bytes match |
| HTTP | Session rotation, HttpOnly and SameSite cookies, POST logout | ID changes after login; cookies protected; GET logout rejected; POST ends session |
| HTTP | Download response | Attachment, nosniff, private/no-store |
| Admin | Users and audit views, metadata access | Faces renders real records; USER cannot open admin pages; no private-content override |

## Actual automated results

Verification on 2 November 2026 used Java 17.0.19, Maven 3.9.11, Hibernate 6.6.59.Final, H2 2.3.232 and embedded Tomcat 10.1.61 with Mojarra 4.0.28 and Weld 5.1.7.Final.

The final `clean verify` run reported **BUILD SUCCESS**. All **21 tests passed**, with **0 failures, 0 errors and 0 skipped**:

| Test class | Kind | Count | Actual result |
|---|---|---:|---|
| `CryptoTest` | Cryptography, hashing and format validation | 6 | Passed |
| `ServiceIT` | Hibernate transactions, permissions, expiry, quota concurrency and failure cleanup | 10 | Passed |
| `WebIT` | Real HTTP requests to the packaged web application on embedded Tomcat | 5 | Passed |

The web suite compiled and rendered JSP pages, registered and authenticated a user, performed a real multipart upload and owner download, rendered admin Facelets through CDI, submitted an actual Faces AJAX account-disable event, checked the disabled user's existing session, and rendered the audit view. It also exercised invalid/missing CSRF tokens on JSP and both kinds of Faces POST. The suite uses a per-test isolated service with test keys and H2; it does not use production environment secrets.

Raw Maven evidence is generated in `target/surefire-reports` and `target/failsafe-reports`. The local build transcript is `.tools/verify.log`; `.tools` and `target` are ignored by Git. Run the command below to regenerate evidence:

```powershell
mvn -B -ntp clean verify
```

When using the project-local Maven downloaded for this workspace:

```powershell
& '.\.tools\apache-maven-3.9.11\bin\mvn.cmd' -B -ntp '-Dmaven.repo.local=.tools/repository' clean verify
```

Earlier verification found and corrected lazy-proxy field access and the embedded container's missing WebSocket support. The final successful results above are from the corrected code. Tomcat emitted informational JAR-scanning messages and Java-module warnings for optional shutdown memory-leak checks in the embedded harness; they did not fail the application or tests.

## Checks not performed

- **MySQL 8 deployment, migration execution and schema validation:** not run because no MySQL client/server was available on PATH and no configured database was supplied. `V001` and the production `validate` configuration are delivered, but they have not been verified against a running MySQL server in this environment.
- **Standalone Tomcat distribution with production environment variables and admin bootstrap CLI:** not run. The test uses the same application web configuration and packaged resources on embedded Tomcat, but supplies an isolated test service rather than connecting to MySQL.
- **Manual browser appearance, keyboard and mobile review:** not performed; no screenshots are claimed. Local responsive CSS and focus styling are included. Automated HTTP rendering does not replace a visual review.
- **HTTPS connector and Secure-cookie transport:** not run; local tests use HTTP. HttpOnly, SameSite and session rotation were checked; HTTPS instructions are documented.
- **External security audit and malware scanner:** not performed or implemented. Format validation is not malware scanning.

H2 MySQL compatibility mode is useful for isolated service tests, constraints and lock behavior, but it is not MySQL. It differs in SQL types, collation, optimizer and locking details. Tests create/drop only their own H2 schemas; normal MySQL startup always validates an externally migrated schema. Re-run the demo guide against MySQL before a college review.
