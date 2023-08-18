$Token = $args
$ServicePath = Join-Path $env:ProgramFiles (Join-Path "CrowdStrike" "CSFalconService.exe")
if (!(Test-Path $ServicePath)) { throw "Unable to locate $ServicePath" }
$BitValue = if((Get-CimInstance win32_operatingsystem).OSArchitecture -match "64"){ "WOW6432Node\" }
$RegPath = "HKLM:\SOFTWARE\$($BitValue)Microsoft\Windows\CurrentVersion\Uninstall"
if (!(Test-Path $RegPath)) { throw "Unable to locate $RegPath" }
@(Get-ChildItem $RegPath).Where({ $_.GetValue("DisplayName") -match "CrowdStrike(.+)?Sensor" }).foreach{
  if ((Get-Item $ServicePath).VersionInfo.FileVersion -eq $_.GetValue("DisplayVersion")) {
    $UninstallString = if ($_.GetValue("QuietUninstallString")) {
      $_.GetValue("QuietUninstallString")
    } else {
      $_.GetValue("UninstallString")
    }
    if (!$UninstallString) { throw "Failed to find UninstallString value for $($_.GetValue("DisplayName"))" }
    $ArgList = @("/c",$UninstallString)
    if ($Token) { $ArgList += "MAINTENANCE_TOKEN=$Token" }
    "Starting removal of the Falcon sensor"
    [void](Start-Process -FilePath cmd.exe -ArgumentList ($ArgList -join " ") -PassThru)
  }
}