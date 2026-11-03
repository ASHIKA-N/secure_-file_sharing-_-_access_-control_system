# Secure File Sharing and Access Control System

Java 17 application configured for **Oracle Database 21c XE 21.3.0.0.0**. Registered users upload encrypted private files and share download access with expiry and revocation. Administrators manage users and inspect audit metadata.

## Advanced features

The application now includes owner-controlled view/download limits, view-once sessions, access requests, conditional policies, controlled resharing, confidential-file OTP, watermarked viewing/PDF downloads, immutable versions, notifications, rule-based alerts, and tamper-evident audit checkpoints. Read [advanced feature details and configuration](docs/advanced-features.md) and [the updated demo](docs/demo-guide.md).

Existing files and grants migrate through V002 without replacing their encryption key. Local OTP delivery defaults to a clearly labelled development mailbox; real SMTP setup is documented separately. The launcher's Windows-DPAPI configuration now also protects independent OTP and audit-checkpoint secrets.

## Run locally on this computer

From the project folder in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1
```

Open **http://localhost:8080/securefiles/login** and register a user. Stop cleanly from a second PowerShell terminal before rebuilding:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

Wait for the server terminal to finish. A hard interruption can leave a Windows JVM holding WAR libraries open. To use another port:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -Port 8081
```

The launcher uses the local Maven copy in `.tools` (or Maven on PATH), Java 17, the installed Oracle SQL*Plus client and embedded **Tomcat 10.1.61**. No separate Tomcat download is needed for local use. OracleServiceXE and its listener must be running; the database service is `localhost:1521/XEPDB1`.

On its first run, the launcher connects using local Windows Oracle OS authentication (`/ as sysdba`), selects XEPDB1 and creates only the dedicated `SECUREFILES_APP` schema if absent. It generates a random schema password and master key. If the account already exists, it prompts for its existing password and master key instead of resetting anything. Local OS authentication requires the current Windows account to belong to the appropriate Oracle DBA group. Manual setup is described below if that is unavailable.

The launcher builds the WAR, explicitly applies V001 to a new schema and the additive `database/V002__advanced_access.sql` migration to version-1 schemas, and starts Tomcat. Future runs reuse the schema. Hibernate uses **validate**, never create-drop, for the real Oracle database. Normal standalone Tomcat startup does not run migrations.

The database password and master key are protected with **Windows DPAPI** for the current Windows account in ignored `.tools/oracle-local.xml`. They are decrypted into environment variables only at launch. File storage is `.tools/private-storage`, outside the deployed WAR and the Tomcat directory. Protected audit checkpoints are in `.tools/audit-checkpoints` and development-only OTP messages in `.tools/local-mailbox`. Do not delete `.tools/oracle-local.xml` or regenerate the master key if files already exist. Its encryption is tied to the Windows account/profile; back up the master key separately in a password manager before moving to another computer. Back up Oracle data and encrypted storage together. No credentials or keys are committed to Git.

## Build and test

```powershell
.\.tools\apache-maven-3.9.11\bin\mvn.cmd -B -ntp '-Dmaven.repo.local=.tools/repository' clean verify
```

With globally installed Maven, use `mvn -B -ntp clean verify`. The deployable WAR is `target/securefiles.war`. The launcher uses `package -DskipTests` for subsequent starts; run `clean verify` to execute the full suite. Tests use isolated H2 Oracle compatibility mode and embedded Tomcat; they never connect to or modify your Oracle database.

## Manual Oracle setup

Use SQL*Plus or SQL Developer as a database administrator, connected to **XEPDB1**, not CDB$ROOT. Replace the example password:

```sql
CREATE USER securefiles_app IDENTIFIED BY "choose-a-private-password" DEFAULT TABLESPACE users QUOTA 200M ON users;
GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE TO securefiles_app;
```

Connect as `securefiles_app` to XEPDB1 and execute:

```sql
@C:/Users/Ashika/secure_-file_sharing-_-_access_-control_system/database/V001__initial_schema.sql
@C:/Users/Ashika/secure_-file_sharing-_-_access_-control_system/database/V002__advanced_access.sql
COMMIT;
```

This local demo uses the application schema owner. For a separate production runtime user, grant SELECT/INSERT/UPDATE on users, files and grants and only SELECT/INSERT on audit records. Keep migration privileges separate. Account disabling and file tombstones preserve audit references.

Generate a master key once for a new manual installation:

```powershell
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.Dispose()
[Convert]::ToBase64String($keyBytes)
[Array]::Clear($keyBytes, 0, $keyBytes.Length)
```

Save it safely and configure the environment in the shell used to start Tomcat:

```powershell
. .\scripts\configure.ps1 -DatabaseUrl 'jdbc:oracle:thin:@//localhost:1521/XEPDB1' -DatabaseUser 'securefiles_app' -StorageDirectory 'C:\securefiles-data'
```

The script prompts for the schema password, saved master key and independent OTP/audit HMAC secrets. Generate each secret separately using the random-key command above; do not reuse the file master key. `.env.example` documents variables but is not loaded automatically. The storage directory must be absolute and outside Tomcat and its deployed WAR. Do not replace an existing installation's key. Losing the key makes stored files unrecoverable. This is server-side encryption, not end-to-end encryption.

## Create an administrator explicitly

Run this after loading the environment. For the one-command launcher's configuration, run `. .\scripts\run.ps1 -SetupOnly` first in the same shell; it loads the saved credentials without starting Tomcat.

```powershell
$env:SF_ADMIN_NAME = 'Local Administrator'
$env:SF_ADMIN_EMAIL = 'admin@example.test'
$adminSecret = Read-Host 'Choose an admin passphrase of 12-128 characters' -AsSecureString
$env:SF_ADMIN_PASSWORD = [System.Net.NetworkCredential]::new('', $adminSecret).Password
.\.tools\apache-maven-3.9.11\bin\mvn.cmd -B -ntp '-Dmaven.repo.local=.tools/repository' exec:java '-Dexec.mainClass=com.securefiles.config.AdminBootstrap'
Remove-Item Env:SF_ADMIN_PASSWORD
Remove-Variable adminSecret
```

Public registration always creates USER accounts. There is no default admin password or public admin-registration page. Admin role permits metadata management, not private-file access. The admin interface is `/securefiles/admin/users.xhtml`.

## Standalone Tomcat deployment

After manual Oracle configuration or loading the launcher environment, deploy the WAR to a Tomcat 10.1 installation:

```powershell
$env:CATALINA_HOME = 'C:\tools\apache-tomcat-10.1.61'
Copy-Item '.\target\securefiles.war' "$env:CATALINA_HOME\webapps\securefiles.war"
& "$env:CATALINA_HOME\bin\catalina.bat" run
```

Use `SF_COOKIE_SECURE=false` only for localhost HTTP. For HTTPS set it to true and configure Tomcat TLS or a trusted TLS proxy. Cookies are HttpOnly and SameSite=Lax; session IDs rotate on login, only cookie session tracking is allowed, and idle sessions expire after 20 minutes.

## Troubleshooting

| Problem | Action |
|---|---|
| ORA-01031 or ORA-01017 during local setup | Use an OS-authenticated Oracle DBA account for first-time schema creation, or follow manual setup. Never change another account's password to work around this. |
| ORA-12514 | Verify XEPDB1 is open and registered with the listener; use `lsnrctl status`. |
| ORA-12541 | Start the installed Oracle listener and OracleServiceXE. |
| ORA-01017 connecting as app | Check the schema password; existing accounts are never automatically reset. |
| Partial schema after DDL failure | Oracle DDL commits implicitly. Inspect the dedicated schema; setup refuses to overwrite existing tables. |
| Port 8080 busy | Run the launcher with `-Port 8081`. |
| Cannot read saved secrets | Use the same Windows account/profile; DPAPI does not decrypt on another account/computer. |
| Files unavailable | Check the original master key, private storage, owner account and recipient grant. |
| Upload rejected | Only PDF, UTF-8 TXT, PNG and JPEG are allowed, up to 10 MiB; simple single-extension filenames and images at most 25 million pixels. |
| Login temporarily throttled | Wait five minutes after five failed attempts. Tracking is process-local. |

## Architecture and dependencies

Servlet/JSP pages serve users; Faces 4 Facelets with CDI serve administrators. Both use the same service and repository layer. Java 17, Servlet 6.0, JSP 3.1, Tags 3.0, Mojarra 4.0.28, Weld 5.1.7.Final, Hibernate 6.6.59.Final and **Oracle ojdbc11 21.21.0.0** are pinned in `pom.xml`. The newer patched JDBC driver supports the installed 21c server and Java 17. Hibernate detects the Oracle dialect from JDBC metadata. Oracle mappings use NUMBER, RAW, VARCHAR2 and TIMESTAMP WITH TIME ZONE, and identity columns. Empty descriptions and blank searches handle Oracle's empty-string-as-NULL behavior.

- [Architecture and ER diagram](docs/architecture.md)
- [Implementation report](docs/implementation-report.md)
- [Verification](docs/test-cases.md)
- [Three-user demo](docs/demo-guide.md)

Revocation blocks later requests but cannot remove copies already downloaded. There are no public links or inline previews. Format checking is not malware scanning. Ordinary audit records are not tamper-proof; no independent security audit is claimed.

## References

Original application code and local styling; no third-party visual assets reused. Guidance: [Oracle JDBC 21c compatibility](https://docs.oracle.com/en/database/oracle/oracle-database/21/jjdbc/JDBC-getting-started.html), [Hibernate Oracle dialect](https://docs.hibernate.org/orm/6.6/javadocs/org/hibernate/dialect/OracleDialect.html), [Tomcat compatibility](https://tomcat.apache.org/whichversion.html), [Mojarra 4.0 setup](https://github.com/eclipse-ee4j/mojarra/blob/4.0/README.md), [Weld servlet setup](https://docs.jboss.org/weld/reference/5.1.6.Final/en-US/html/environments.html), and OWASP guidance for [uploads](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
