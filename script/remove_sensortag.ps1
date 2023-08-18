param([string]$Tag,[string]$Token)
$ExePath = Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe"
if (Test-Path $ExePath) {
  if ($Token -and $Tag) {
    echo "$Token" | & "$ExePath" set --grouping-tags "$Tag"
  } elseif ($Token) {
    echo "$Token" | & "$ExePath" clear --grouping-tags
  } else {
    & "$ExePath" clear --grouping-tags
  }
} else {
  throw "Not found: $ExePath"
}