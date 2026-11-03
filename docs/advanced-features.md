# Advanced feature implementation

The application still uses Java 17, Servlet/JSP user pages, Faces 4 administrator pages, Hibernate 6.6 and Oracle 21c. PDFBox 3.0.8 and Eclipse Angus Jakarta Mail 2.0.5 were added after checking their official release documentation. No third-party visual assets were added.

## Access settings and consumption

Open My Files → Details → Manage Access Settings. Presets are evaluated on the server and show a separate confirmation page before saving. Custom settings independently control viewing, download transfers, onward delegation, optional UTC expiry, daily access hours, OTP and a pinned or latest-active version. Viewing once means one ten-minute session, no download and no resharing. Download once means one transfer with no viewing or resharing. Download only leaves the transfer count configurable. Editing preserves all consumed counts; limits below a consumed count are rejected. No counter-reset feature is provided.

`PermissionEngine` resolves the actor, active original owner, logical file, active version and complete grant ancestry. It checks every ancestor's revocation, expiry, recipient/creator account, allowed action and daily schedule. Start is inclusive and end exclusive. Overnight windows are supported. Schedules use IANA zone names and local wall-clock time: both occurrences of a repeated DST minute qualify, while a skipped minute does not exist. Every ancestor window applies, so a child's window can only narrow effective access.

`AdvancedService` prepares/decrypts content outside database locks. It then locks the logical file and ancestor budgets in ascending grant-ID order, rechecks access, consumes a single-use OTP permit when required and increments each relevant ancestor counter atomically. An unrelated recipient or administrator receives no private content. The per-file lock serializes sharing, revocation, version changes and counter reservations for this demonstration.

Limited downloads use a CSRF-protected POST after confirmation. The legacy GET download URL redirects to confirmation for counted/OTP-protected grants. Disabled downloads are also denied in the service. HTTP Range/resume is rejected with 416. Counting occurs after authenticated decryption and PDF processing, just before the response is ready. Corrupt files and failed preparation do not consume allowance. Once ready/start is recorded, a failed connection or retry does not refund it; the server cannot know whether a recipient saved the file.

## Viewer

PDF pages are rendered to PNG on the server; TXT is drawn as text in a PNG, and PNG/JPEG images are subsampled to bounded dimensions. Original PDF or text bytes are never sent by a view-only endpoint. Every served page contains the recipient identity and session UTC timestamp. Screenshots, recording and browser capture remain possible; this is not DRM.

A viewing session has an unpredictable ID and a separate HMAC-derived secret kept in the authenticated HTTP session. URLs contain only the public session record ID, not the secret. Sessions bind user, logical file, immutable content version and grant. Opening reserves one view after the first page can be rendered. Duplicate initiation IDs and an already active user/version/grant session are reused. Refresh and page requests do not consume more views. Close Viewer invalidates the session; expiry is authoritative because browser-close events are unreliable. There are no refunds. A classification/policy change requiring OTP blocks a viewer that was not OTP-authorized.

Every page request checks session ownership and secret, account state, version status, complete grant chain, hours, expiry and revocation before rendering and again before returning bytes. An archived version or revoked ancestor immediately blocks subsequent viewer resources, including resources from an otherwise unexpired session.

PDF parsing/rendering/watermarking runs in a separate Java worker with a 160 MiB heap, an eight-second processing timeout and at most two concurrent workers. Worker environment variables containing database, mail and encryption secrets are removed. Input is at most 10 MiB, PDF count at most 40 pages, render dimensions at most 1400×1800 and output at most 24 MiB. Text viewing is bounded to 250 KB and 40 pages. Image viewer output is capped at three million pixels. Workers use pipes and in-memory buffers; no plaintext derivative is saved permanently. Encrypted, signed or malformed PDFs are refused. Altering a signed PDF could invalidate its signature, so it is not offered as a watermarked derivative.

PDF downloads are personalized with recipient name, email, UTC time and a nonsecret audit reference on every page. The encrypted original is unchanged. A local Unicode TrueType font is used (`SF_PDF_FONT`, or Windows Arial / Linux DejaVu Sans); characters unavailable in that font are replaced safely, so configure a suitable font for the required writing system. Long identity values wrap. Download modification is limited to PDFs. Watermarks deter copying and assist tracing; they do not prove who leaked a file or guarantee removal resistance.

## Requests and delegation

Files are unlisted by default. Owners must explicitly list a logical file in the authenticated catalogue before another account can request it. Catalogue listing exposes its display name, owner and description, not its content. Guessed private IDs cannot submit a request or reveal metadata. One pending request per file/requester is enforced by a nullable unique pending key and a logical-file lock. PENDING requests can be approved with an actual policy, rejected by the owner, or cancelled by the requester. Decision history and notifications are persisted. Deleting a file cancels its pending requests.

Sharing is denied by default to recipients with the exact required message. The original owner's explicit permission is necessary for delegation. Children cannot enable actions or OTP exemptions beyond ancestors, exceed ancestor expiry, change an ancestor's version pin, share to the owner/ancestor or create a second effective grant for the same file/user. Three recipient levels are supported. Limited ancestor budgets are shared by all descendants and are consumed together. Parent revocation or loss of onward-delegation permission invalidates descendants. The owner sees all parent relationships and counters; a delegator can manage only their created branches. These rules govern this application; a saved local copy can still be forwarded externally.

## OTP delivery and configuration

CONFIDENTIAL files always require OTP for a new view or download, including owner access. A NORMAL file can require OTP per grant. Challenges bind user, file, version, grant and operation. Six-digit codes use SecureRandom and expire exactly five minutes after issue. Five guesses are allowed, resending waits 60 seconds and at most five challenges may be issued per account in ten minutes. New sends supersede outstanding challenges for the same file/operation. Failed delivery invalidates its challenge. The database stores an HMAC verifier, never the numeric code. A successful verification consumes the challenge and issues a hashed, single-use two-minute operation permit; current access is checked again when that permit is used.

The launcher defaults to **development-only LOCAL mailbox mode**. No email is sent. Only the signed-in user's messages are visible at My Local Mailbox from the OTP page, and local messages are removed after ten minutes. This mode deliberately saves readable demo messages in a private directory. Do not use it as real email delivery.

For SMTP, set these environment variables before the launch command:

```powershell
$env:SF_MAIL_MODE = 'SMTP'
$env:SF_SMTP_HOST = 'smtp.your-provider.example'
$env:SF_SMTP_PORT = '587'
$env:SF_SMTP_USER = 'your-smtp-user'
$smtpSecret = Read-Host 'SMTP password' -AsSecureString
$env:SF_SMTP_PASSWORD = [System.Net.NetworkCredential]::new('', $smtpSecret).Password
$env:SF_SMTP_FROM = 'your-verified-sender@example.test'
```

SMTP requires STARTTLS and hostname verification. Connection/read/write timeouts are five seconds. No mail delivery occurs while holding policy locks. Actual external SMTP delivery requires your provider credentials and an approved sender; local tests do not claim real email was sent.

The launcher adds independent random `SF_OTP_SECRET` and `SF_AUDIT_SECRET` values to the existing Windows-DPAPI configuration. It preserves the original master key and database password. The OTP secret protects low-entropy code verifiers. The audit secret authenticates external checkpoints. Manual installations must generate separate random Base64 values of at least 32 bytes and configure `SF_CHECKPOINT_DIR` and `SF_LOCAL_MAILBOX_DIR` outside Tomcat. Back up all secrets separately from Oracle and encrypted storage.

## Alerts

Persistent audit events support four transparent rules: ten denied file-access attempts in five minutes; five denied reshares in five minutes; twenty download starts in ten minutes; and attempts against ten distinct inaccessible file IDs in five minutes. Thresholds can be set with `SF_ALERT_DENIED`, `SF_ALERT_RESHARE`, `SF_ALERT_DOWNLOADS` and `SF_ALERT_DISTINCT`. Cooldown defaults to 900 seconds (`SF_ALERT_COOLDOWN_SECONDS`). Alerts are deduplicated per actor/rule/scope. No IP addresses or forwarded headers are used. Audit events and alerts are retained for the project lifetime; local OTP mailbox messages have a ten-minute retention window.

Administrators see global alerts and can acknowledge or resolve them. Owners see a separate scope counting only events for their files, with no unrelated account details. Alerts indicate unusual activity, not confirmed abuse. Accounts are never disabled automatically.

## Audit chain and checkpoints

All application audit appends lock a single `AuditHead` row. Sequences are unique, gap-free across committed appends and linked with SHA-256. Canonical encoding is big-endian: 32-bit format version 1, 64-bit chain sequence, 64-bit row ID, then actor ID, action, logical-file ID, served-version ID, outcome, reason, UTC ISO instant and attempted-file-ID hash as UTF-8 strings. Each string has a signed 32-bit byte-length prefix; null is -1. The event digest is SHA-256 of the previous hash's 32 decoded bytes followed by this encoding. Raw viewing secrets, OTPs, passwords, encryption keys and file content are never included.

Checkpoint files contain five newline-separated fields: format version, sequence, chain hash, UTC time and HMAC-SHA256 over the first four fields joined with newlines. They are exported to a private directory outside Oracle with a separate secret. Administrator actions can verify the chain or export a checkpoint; periodic maintenance also exports checkpoints. Verification reads the external files independently of their metadata table and reports the first inconsistency or a rewrite/truncation relative to a checkpoint.

Migrated historical audit rows are chained at the first advanced startup in their original ID order. This establishes a baseline; it does not prove those earlier rows were authentic before migration. A database-only chain cannot detect every complete rewrite without a protected checkpoint. An attacker who controls the server, its filesystem and checkpoint secret can forge evidence. This is tamper-evident within that trust boundary, not tamper-proof storage or blockchain.

## Versions and migration

`StoredFile` is the logical file; `FileVersion` owns immutable encrypted content. V002 backfills one version for every original file using the original encryption binding and storage ID, so existing bytes are not decrypted or rewritten. Legacy encryption columns remain on StoredFile for compatibility, but advanced reads use FileVersion. Existing DOWNLOAD grants remain download-only with unlimited transfers, no viewing/resharing, and unchanged expiry/revocation. Counters start at zero because the original application did not record trustworthy usage counts.

New versions receive their own encryption keys/IVs and monotonically increasing version numbers. Latest-active grants resolve at operation/session creation; pinned grants cannot fetch other versions. An existing viewer stays pinned. Publishing a version does not reset limits. Archiving blocks both new and existing requests for that version. Archived bytes continue counting toward quota; deleting the logical file revokes access and schedules all encrypted versions for physical cleanup.

The explicit local setup applies V001 to a new schema, then V002. Existing version-1 schemas receive only V002. Oracle DDL commits implicitly: backup metadata before upgrading and inspect partial migrations rather than dropping tables automatically. Production Hibernate always validates the resulting mappings.

## References

[PDFBox release](https://pdfbox.apache.org/download.html), [PDFBox 3 migration and memory APIs](https://pdfbox.apache.org/3.0/migration.html), [Eclipse Angus Mail](https://eclipse-ee4j.github.io/angus-mail/). PDFBox is Apache-2.0 and Angus Mail carries its upstream Eclipse licensing; dependency licenses remain with their authors.
