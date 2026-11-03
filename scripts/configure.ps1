# Dot-source this script in the same PowerShell window used for Maven and Tomcat.
param(
    [string]$StorageDirectory = 'C:\securefiles-data',
    [string]$DatabaseUrl = 'jdbc:oracle:thin:@//localhost:1521/XEPDB1',
    [string]$DatabaseUser = 'securefiles_app'
)
$env:SF_DB_URL = $DatabaseUrl
$env:SF_DB_USER = $DatabaseUser
$databaseSecret = Read-Host "Oracle password for $DatabaseUser" -AsSecureString
$env:SF_DB_PASSWORD = [System.Net.NetworkCredential]::new('', $databaseSecret).Password
$env:SF_STORAGE_DIR = $StorageDirectory
$env:SF_COOKIE_SECURE = 'false'
$env:SF_QUOTA_BYTES = '104857600'
$masterSecret = Read-Host 'Existing Base64 master key (keep it safe; do not generate a new key for existing files)' -AsSecureString
$env:SF_MASTER_KEY = [System.Net.NetworkCredential]::new('', $masterSecret).Password
Remove-Variable databaseSecret, masterSecret
foreach ($secretName in @('SF_OTP_SECRET', 'SF_AUDIT_SECRET')) {
    $secretValue = Read-Host "Existing Base64 $secretName (independent random secret of at least 32 bytes)" -AsSecureString
    [Environment]::SetEnvironmentVariable($secretName, [System.Net.NetworkCredential]::new('', $secretValue).Password, 'Process')
}
$privateParent = Split-Path -Parent $StorageDirectory
$env:SF_CHECKPOINT_DIR = Join-Path $privateParent 'securefiles-audit-checkpoints'
$env:SF_LOCAL_MAILBOX_DIR = Join-Path $privateParent 'securefiles-local-mailbox'
if (-not $env:SF_MAIL_MODE) { $env:SF_MAIL_MODE = 'LOCAL' }
