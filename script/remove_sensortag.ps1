param([Parameter(Position=1)][string]$Token)
$ExePath = Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe"
if (Test-Path $ExePath) {
  if ($Token) {
    echo "$Token" | & "$ExePath" clear --grouping-tags
  } else {
    & "$ExePath" clear --grouping-tags
  }
} else {
  throw "Not found: $ExePath"
}