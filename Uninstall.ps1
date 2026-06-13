# Uninstall.ps1 — removes all artifacts for EXE and sideload builds.
# Safe to run regardless of which build was deployed; missing artifacts are silently skipped.
# Run from any privilege level — only HKCU and APPDATA are touched.

$runKeyName = 'OneDriveUpdateSync'
$procName   = 'OneDriveUpdateSync'     # without .exe for Stop-Process
$destDir    = Join-Path $env:APPDATA 'OneDrive\Updates'
$destExe    = Join-Path $destDir ($procName + '.exe')
$runKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Stop the persistence process
Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue

# Remove the HKCU run key (EXE and sideload builds)
Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue

# Delete the persistence folder
#   EXE builds:      contains OneDriveUpdateSync.exe only
#   Sideload builds: contains OneDriveUpdateSync.exe + forwarded DLLs
Remove-Item -Path $destDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[+] Uninstall complete." -ForegroundColor Green
