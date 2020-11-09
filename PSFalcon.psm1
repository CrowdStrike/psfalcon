$Endpoints = Get-Content "$PSScriptRoot\Data\Endpoints.json" -ErrorAction Stop | ConvertFrom-Json
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.fullname
    } catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
if (-not($Script:Falcon)) {
    $Script:Falcon = [Falcon]::New($Endpoints)
}
Write-Host "Imported PSFalcon. Review 'Get-Command -Module PSFalcon' and '<Command> -Help' for details."