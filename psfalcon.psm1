$PSD = Import-PowerShellDataFile $PSScriptRoot\psfalcon.psd1
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
$EndpointFiles = @(Get-ChildItem -Path $PSScriptRoot\Data\*\*.psd1 -ErrorAction SilentlyContinue)
foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.fullname
    }
    catch {
        Write-Error -Message "Failed import of psfalcon function $($Import.fullname): $_"
    }
}
$Endpoints = foreach ($Import in $EndpointFiles) {
    try {
        Import-PowerShellDataFile $Import.fullname
    }
    catch {
        Write-Error -Message "Failed import of psfalcon data file $($Import.fullname): $_"
    }
}
if (-not($Script:Falcon)) {
    $Script:Falcon = [Falcon]::New($Endpoints)
}
Write-Host "Imported psfalcon v$($PSD.ModuleVersion). See 'Get-Command -Module psfalcon' and '<Command> -Help'."