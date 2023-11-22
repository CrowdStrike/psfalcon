param([string]$Token,[string]$Tag)
$ExePath=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe"
if (Test-Path $ExePath) {
  if ($Token) {
    echo "$Token" | & "$ExePath" set --grouping-tags "$Tag"
  } else {
    & "$ExePath" set --grouping-tags "$Tag"
  }
} else {
  throw "Not found: $ExePath"
}