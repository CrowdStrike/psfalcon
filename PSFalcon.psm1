@(
    # Import class, public and private functions
    Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
    Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
    Get-ChildItem -Path $PSScriptRoot\Class\Class.ps1
).foreach{
    try { . $_.FullName } catch { throw $_ }
}
# Import object formats for successful API responses
$Script:Response = try { Get-Content $PSScriptRoot\Response\Response.json -EA 0 | ConvertFrom-Json } catch {}