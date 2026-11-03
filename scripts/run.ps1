param([switch]$SetupOnly, [int]$Port = 8080)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This launcher uses Windows DPAPI and local Oracle OS authentication.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $localMaven = Join-Path $projectRoot '.tools\apache-maven-3.9.11\bin\mvn.cmd'
    $maven = if (Test-Path -LiteralPath $localMaven) { $localMaven } else { (Get-Command mvn.cmd -ErrorAction Stop).Source }
    New-Item -ItemType Directory -Force '.tools' | Out-Null
    $secretFile = Join-Path $projectRoot '.tools\oracle-local.xml'
    if (-not (Test-Path -LiteralPath $secretFile)) {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $databaseBytes = New-Object byte[] 18
            $masterBytes = New-Object byte[] 32
            $rng.GetBytes($databaseBytes)
            $rng.GetBytes($masterBytes)
            $databasePassword = [Convert]::ToBase64String($databaseBytes)
            $masterKey = [Convert]::ToBase64String($masterBytes)
        } finally { $rng.Dispose() }
        # Never reset an existing user's password or alter unrelated database accounts.
        $setupSql = @"
WHENEVER SQLERROR EXIT FAILURE
SET ECHO OFF FEEDBACK OFF VERIFY OFF HEADING OFF
ALTER SESSION SET CONTAINER=XEPDB1;
SELECT COUNT(*) FROM dba_users WHERE username='SECUREFILES_APP';
EXIT
"@
        $existing = $setupSql | & sqlplus -L -S '/ as sysdba'
        if ($LASTEXITCODE -ne 0) { throw 'Oracle local OS authentication failed. Use a Windows account allowed to connect as SYSDBA, or configure the schema manually as described in README.md.' }
        if (($existing -join "`n") -match '(?m)^\s*1\s*$') {
            $passwordInput = Read-Host 'Password for existing Oracle SECUREFILES_APP schema' -AsSecureString
            $databasePassword = [System.Net.NetworkCredential]::new('', $passwordInput).Password
            $keyInput = Read-Host 'Existing Base64 master key (leave blank only for a new installation)' -AsSecureString
            $existingKey = [System.Net.NetworkCredential]::new('', $keyInput).Password
            if ($existingKey) { $masterKey = $existingKey }
            elseif (Test-Path -LiteralPath '.tools\private-storage') { throw 'Restore the original master key before using existing storage.' }
        } else {
            $createSql = @"
WHENEVER SQLERROR EXIT FAILURE
SET ECHO OFF FEEDBACK OFF VERIFY OFF DEFINE OFF
ALTER SESSION SET CONTAINER=XEPDB1;
CREATE USER securefiles_app IDENTIFIED BY "$databasePassword" DEFAULT TABLESPACE users QUOTA 200M ON users;
GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE TO securefiles_app;
EXIT
"@
            $createSql | & sqlplus -L -S '/ as sysdba'
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the dedicated Oracle application schema.' }
        }
        $saved = [pscustomobject]@{
            Password = ConvertTo-SecureString $databasePassword -AsPlainText -Force
            MasterKey = ConvertTo-SecureString $masterKey -AsPlainText -Force
        }
        # DPAPI encrypts both values for the current Windows user.
        $saved | Export-Clixml -LiteralPath $secretFile
        $acl = Get-Acl -LiteralPath $secretFile
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $secretFile -AclObject $acl
    }
    $saved = Import-Clixml -LiteralPath $secretFile
    # Extend saved configuration without replacing the file-encryption master key.
    $advancedSecretsChanged = $false
    foreach ($property in @('OtpSecret','AuditSecret')) {
        if (-not $saved.PSObject.Properties[$property]) {
            if ($property -eq 'AuditSecret' -and (Test-Path -Path (Join-Path $projectRoot '.tools\audit-checkpoints\*.checkpoint'))) {
                throw 'Protected checkpoints already exist. Restore the original AuditSecret instead of generating a replacement.'
            }
            $newBytes = New-Object byte[] 32
            $newRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $newRandom.GetBytes($newBytes) } finally { $newRandom.Dispose() }
            $protected = ConvertTo-SecureString ([Convert]::ToBase64String($newBytes)) -AsPlainText -Force
            $saved | Add-Member -NotePropertyName $property -NotePropertyValue $protected
            $advancedSecretsChanged = $true
        }
    }
    if ($advancedSecretsChanged) { $saved | Export-Clixml -LiteralPath $secretFile }
    $env:SF_OTP_SECRET = [System.Net.NetworkCredential]::new('', $saved.OtpSecret).Password
    $env:SF_AUDIT_SECRET = [System.Net.NetworkCredential]::new('', $saved.AuditSecret).Password
    $env:SF_CHECKPOINT_DIR = Join-Path $projectRoot '.tools\audit-checkpoints'
    $env:SF_LOCAL_MAILBOX_DIR = Join-Path $projectRoot '.tools\local-mailbox'
    if (-not $env:SF_MAIL_MODE) { $env:SF_MAIL_MODE = 'LOCAL' }
    $env:SF_DB_URL = 'jdbc:oracle:thin:@//localhost:1521/XEPDB1'
    $env:SF_DB_USER = 'securefiles_app'
    $env:SF_DB_PASSWORD = [System.Net.NetworkCredential]::new('', $saved.Password).Password
    $env:SF_MASTER_KEY = [System.Net.NetworkCredential]::new('', $saved.MasterKey).Password
    $env:SF_STORAGE_DIR = Join-Path $projectRoot '.tools\private-storage'
    $env:SF_COOKIE_SECURE = 'false'
    $env:SF_QUOTA_BYTES = '104857600'
    $env:SF_PORT = "$Port"
    $ErrorActionPreference = 'Continue'
    & $maven -B -ntp '-Dmaven.repo.local=.tools/repository' '-DskipTests' package
    if ($LASTEXITCODE -ne 0) { throw 'Maven build failed.' }
    if ($SetupOnly) {
        & $maven -B -ntp '-Dmaven.repo.local=.tools/repository' exec:java '-Dexec.mainClass=com.securefiles.config.OracleSetup' '-Dexec.cleanupDaemonThreads=false'
    } else {
        & $maven -B -ntp '-Dmaven.repo.local=.tools/repository' exec:java '-Dexec.mainClass=com.securefiles.LocalServer' '-Dexec.classpathScope=test' '-Dexec.cleanupDaemonThreads=false'
    }
    if ($LASTEXITCODE -ne 0) { throw 'Oracle setup or application startup failed.' }
} finally { Pop-Location }
