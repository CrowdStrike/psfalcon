$Public = Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
$Private = Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
@($Public + $Private).foreach{
    try {
        . $_.FullName
    } catch {
        throw $_
    }
}