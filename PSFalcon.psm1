# Import public and private functions
$imports = @(
    Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
    Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
    Get-ChildItem -Path $PSScriptRoot\Class\Class.ps1
)

$imports.foreach{
    try {
        . $_.FullName
    }
    catch {
        throw $_
    }
}