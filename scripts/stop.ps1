$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$serverDirectory = Join-Path $projectRoot '.tools\tomcat'
if (-not (Test-Path -LiteralPath $serverDirectory)) { throw 'No local server directory exists.' }
Set-Content -LiteralPath (Join-Path $serverDirectory 'stop.request') -Value 'Stop the local Secure File Sharing server.'
Write-Output 'Stop requested. Wait for the running server terminal to finish before rebuilding.'
