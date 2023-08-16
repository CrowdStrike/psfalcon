$t=$args
$sp=Join-Path $env:ProgramFiles (Join-Path "CrowdStrike" "CSFalconService.exe")
if (!(Test-Path $sp)) { throw "Unable to locate $sp" }
$bv=if((Get-CimInstance win32_operatingsystem).OSArchitecture -match "64"){ "WOW6432Node\" }
$rp="HKLM:\SOFTWARE\$($bv)Microsoft\Windows\CurrentVersion\Uninstall"
if (!(Test-Path $rp)) { throw "Unable to locate $rp" }
@(gci $rp).Where({ $_.GetValue("DisplayName") -match "CrowdStrike(.+)?Sensor" }).foreach{
  if ((gi $sp).VersionInfo.FileVersion -eq $_.GetValue("DisplayVersion")) {
    $us=if ($_.GetValue("QuietUninstallString")) {
      $_.GetValue("QuietUninstallString")
    } else {
      $_.GetValue("UninstallString")
    }
    if (!$us) { throw "Failed to find UninstallString value for $($_.GetValue("DisplayName"))" }
    $al=@("/c",$us)
    if ($t) { $al+="MAINTENANCE_TOKEN=$t" }
    "Starting removal of the Falcon sensor"
    [void](start -FilePath cmd.exe -ArgumentList ($al -join " ") -PassThru)
  }
}