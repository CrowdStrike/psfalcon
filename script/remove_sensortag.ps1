param([string]$Tag,[string]$Token)
$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";
if (Test-Path $E) {
  if ($Token -and $Tag) {
    echo "$Token" | & "$E" set --grouping-tags "$Tag"
  } elseif ($Token) {
    echo "$Token" | & "$E" clear --grouping-tags
  } else {
    & "$E" clear --grouping-tags
  }
} else {
  throw "Not found: $E"
}