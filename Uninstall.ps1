#Requires -RunAsAdministrator

$taskName = 'Office Telemetry Agent'
$procName = 'msoia.exe'
$destDir  = Join-Path $env:APPDATA 'Microsoft\Office\Updates\'
$destExe  = Join-Path $destDir $procName

# Stop process
Stop-Process -Name ([IO.Path]::GetFileNameWithoutExtension($procName)) -Force -ErrorAction SilentlyContinue

# Remove scheduled task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Rebuild the exact exclusion path chain the installer added (every '\'-terminated prefix)
$chain = @()
$path  = $destDir.TrimEnd('\') + '\'
for ($i = 0; $i -lt $path.Length; $i++) {
    if ($path[$i] -eq '\') { $chain += $path.Substring(0, $i + 1) }
}
$chain += $destExe

Remove-MpPreference -ExclusionPath  $chain    -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess $procName -ErrorAction SilentlyContinue

# Delete persistence folder
Remove-Item -Path $destDir -Recurse -Force -ErrorAction SilentlyContinue
