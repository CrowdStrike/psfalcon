$Public = Get-ChildItem -Path $PSScriptRoot\Public\*.ps1
$Private = Get-ChildItem -Path $PSScriptRoot\Private\Private.ps1
@($Public + $Private).foreach{
    try {
        . $_.FullName
    }
    catch {
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
    }
    else {
        Get-ChildItem -Path $PSScriptRoot\Data\$Key.psd1
    }
    ($DataFiles).foreach{
        try {
            (Import-PowerShellDataFile $_.FullName).GetEnumerator().foreach{
                $Data.$Key.Add($_.Key, $_.Value)
            }
        }
        catch {
            throw $_
        }
    }
}
$Script:Falcon = [Falcon]::New($Data)