$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
$EndpointFiles = @(Get-ChildItem -Path $PSScriptRoot\Data\*\*.psd1 -ErrorAction SilentlyContinue)
foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.fullname
    }
    catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
$Endpoints = foreach ($Import in $EndpointFiles) {
    try {
        Import-PowerShellDataFile $Import
    }
    catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
if (-not($Script:Falcon)) {
    $Script:Falcon = [Falcon]::New($Endpoints)
}
Write-Host "Imported PSFalcon. Review 'Get-Command -Module PSFalcon' and '<Command> -Help' for details."