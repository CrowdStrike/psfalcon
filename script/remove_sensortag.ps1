param([Parameter(Mandatory,Position=1)][string]$Tag,[Parameter(Position=2)][string]$Token)
$ExePath = Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe"
if (Test-Path $ExePath) {
  if ($Token) {
    echo "$Token" | & "$ExePath" set --grouping-tags "$Tag"
  } else {
    & "$ExePath" set --grouping-tags "$Tag"
  }
} else {
  throw "Not found: $ExePath"
}