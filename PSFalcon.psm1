$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
$Endpoints = @(Get-ChildItem -Path $PSScriptRoot\Data\Endpoints\*\*.psd1 -ErrorAction SilentlyContinue)
$Responses = @(Get-ChildItem -Path $PSScriptRoot\Data\Responses\*.psd1 -ErrorAction SilentlyContinue)
foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.fullname
    }
    catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
$EndpointData = foreach ($Import in $Endpoints) {
    try {
        Import-PowerShellDataFile $Import
    }
    catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
$ResponseData = foreach ($Import in $Responses) {
    try {
        Import-PowerShellDataFile $Import
    }
    catch {
        Write-Error -Message "Failed import of $($Import.fullname): $_"
    }
}
if (-not($Script:Falcon)) {
    $Script:Falcon = [Falcon]::New($EndpointData, $ResponseData)
}
Write-Host "Imported PSFalcon. Review 'Get-Command -Module PSFalcon' and '<Command> -Help' for details."