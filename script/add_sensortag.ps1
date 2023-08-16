param([string]$Token,[string]$Tag)
$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe"
if (Test-Path $E) {
  if ($Token) {
    echo "$Token" | & "$E" set --grouping-tags "$Tag"
  } else {
    & "$E" set --grouping-tags "$Tag"
  }
} else {
  throw "Not found: $E"
}