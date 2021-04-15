$Public = Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
$Private = Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
@($Public + $Private).foreach{
    try {
        . $_.FullName
    } catch {
        throw $_
    }
}
$Data = @{
    Endpoints = @{}
    ItemTypes = @{}
    Parameters = @{}
    Patterns = @{}
    Schema = @{}
}
($Data.Keys).foreach{
    $Key = $_
    $DataFiles = if ($_ -eq 'Endpoints') {
        Get-ChildItem -Path $PSScriptRoot\Data\$Key\*.psd1
    } else {
        Get-ChildItem -Path $PSScriptRoot\Data\$Key.psd1
    }
    ($DataFiles).foreach{
        try {
            (Import-PowerShellDataFile $_.FullName).GetEnumerator().foreach{
                $Data.$Key.Add($_.Key, $_.Value)
            }
        } catch {
            throw $_
        }
    }
}
# Create script variable to contain API, credential and module data
$Script:Falcon = [Falcon]::New($Data)
if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
    # Add TLS2 as .NET SecurityProtocol for communication with APIs
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}
if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Add System.Net.Http in PowerShell Desktop
    Add-Type -AssemblyName System.Net.Http
}