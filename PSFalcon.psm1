@(
    # Import class, public and private functions
    Get-ChildItem -Path $PSScriptRoot\class\Class.ps1
    Get-ChildItem -Path $PSScriptRoot\private\Private.ps1
    Get-ChildItem -Path $PSScriptRoot\public\*.ps1
).foreach{
    try { . $_.FullName } catch { throw $_ }
}