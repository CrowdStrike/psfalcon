@(
  # Import class, public and private functions
  Get-ChildItem -Path (Join-Path (Join-Path $PSScriptRoot class) Class.ps1)
  Get-ChildItem -Path (Join-Path (Join-Path $PSScriptRoot private) Private.ps1)
  Get-ChildItem -Path (Join-Path (Join-Path $PSScriptRoot public) *.ps1)
).foreach{
  try { . $_.FullName } catch { throw $_ }
}
# Check for available module update from PowerShell Gallery
Invoke-UpdateCheck $PSScriptRoot