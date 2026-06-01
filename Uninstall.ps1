#Requires -RunAsAdministrator
# Uninstall.ps1 — removes all artifacts for all 4 build types.
# Safe to run regardless of which build was deployed; missing artifacts are silently skipped.

$taskName   = 'Office Telemetry Agent'
$runKeyName = 'OfficeUpdate'
$procName   = 'msoia'                  # without .exe for Stop-Process
$destDir    = Join-Path $env:APPDATA 'Microsoft\Office\Updates\'
$destExe    = Join-Path $destDir ($procName + '.exe')
$runKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# ============================================================
# All builds: stop the persistence process
# ============================================================
Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue

# ============================================================
# Build: exe  (build.bat)
#   Installed: %APPDATA%\Microsoft\Office\Updates\msoia.exe
#   Persist:   HKCU\...\Run "OfficeUpdate" = "<destExe>"
# ============================================================
# ============================================================
# Build: sideload  (build.bat sideload)
#   Installed: %APPDATA%\Microsoft\Office\Updates\msoia.exe + *.dll
#   Persist:   HKCU\...\Run "OfficeUpdate" = "<destExe> /pf"
# ============================================================
Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue

# ============================================================
# Build: exe uac  (build.bat uac)
#   Installed: %APPDATA%\Microsoft\Office\Updates\msoia.exe
#   Persist:   Scheduled task "Office Telemetry Agent" → msoia.exe (RunLevel Highest)
#   WD excl:   ExclusionPath chain + ExclusionProcess msoia.exe
# ============================================================
# ============================================================
# Build: sideload uac  (build.bat sideload uac)
#   Installed: %APPDATA%\Microsoft\Office\Updates\msoia.exe + *.dll
#   Persist:   Scheduled task "Office Telemetry Agent" → msoia.exe /pf (RunLevel Highest)
#   WD excl:   ExclusionPath chain + ExclusionProcess msoia.exe
# ============================================================
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$chain = @()
$path  = $destDir.TrimEnd('\') + '\'
for ($i = 0; $i -lt $path.Length; $i++) {
    if ($path[$i] -eq '\') { $chain += $path.Substring(0, $i + 1) }
}
$chain += $destExe
Remove-MpPreference -ExclusionPath    $chain            -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess ($procName + '.exe') -ErrorAction SilentlyContinue

# ============================================================
# All builds: delete the persistence folder
#   exe:      contains msoia.exe only
#   sideload: contains msoia.exe + forwarded DLLs
# ============================================================
Remove-Item -Path $destDir -Recurse -Force -ErrorAction SilentlyContinue
