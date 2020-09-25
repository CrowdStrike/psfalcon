# Import Public and Private functions
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)

foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.fullname
    } catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
# Create variable to store module data and set default hostname
if (-not($Falcon)) {
    $Global:Falcon = [Falcon]::New('https://api.crowdstrike.com')
}
# Import endpoint data
$Falcon.Endpoints = Get-Content "$PSScriptRoot\Data\Endpoints.json" | ConvertFrom-Json

Write-Warning "PSFalcon has modified commands. Review 'Get-Command -Module PSFalcon' and '<Command> -Help'"