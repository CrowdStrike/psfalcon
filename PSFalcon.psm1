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
    $Script:Falcon = [Falcon]::New((Get-Content "$PSScriptRoot\Data\Endpoints.json" | ConvertFrom-Json))
}
$Param = @{
    Object = "Imported PSFalcon. Review 'Get-Command -Module PSFalcon' and '<Command> -Help' for details."
    ForeGroundColor = "DarkRed"
}
Write-Host @Param