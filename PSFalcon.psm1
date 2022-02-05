@(
    # Import class, public and private functions
    Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
    Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
    Get-ChildItem -Path $PSScriptRoot\Class\Class.ps1
).foreach{ try { . $_.FullName } catch { throw $_ }}