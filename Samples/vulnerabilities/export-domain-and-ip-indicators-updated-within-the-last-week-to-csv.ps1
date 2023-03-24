#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
param(
    [Parameter(Position=1)]
    [int]$Days = 7,
    [Parameter(Position=2)]
    [string[]]$Fields = @('last_seen','mac_address','serial_number','external_ip')
)
# Force 'device_id' as a field to be used for matching results and set export filename
if ($Fields -notcontains 'device_id') { $Fields += ,'device_id' }
$ExportName = Join-Path (Get-Location).Path "Vulnerabilities_$(
    (Get-Date).AddDays(-$Days).ToString('yyyyMMdd'))_to_$(Get-Date -Format FileDate).csv"

# Gather vulnerabilities within date range (default: last 7 days) and export to CSV
$Param = @{
    Filter = "created_timestamp:>'last $Days days'"
    Detailed = $true
    All = $true
    Verbose = $true
}
Get-FalconVulnerability @Param | Export-FalconReport -Path $ExportName

if (Test-Path $ExportName) {
    # Import newly created vulnerability report
    $CSV = Import-Csv -Path $ExportName

    # Gather host ids
    $HostIds = ($CSV | Group-Object aid).Name

    # Get detailed information about hosts to append to CSV
    $Param = @{ Id = $HostIds; Verbose = $true }
    $HostInfo = Get-FalconHost @Param | Select-Object $Fields

    foreach ($Item in $HostInfo) {
        foreach ($Result in ($CSV | Where-Object { $_.aid -eq $Item.device_id })) {
            foreach ($Property in ($Item.PSObject.Properties | Where-Object { $_.Name -ne 'device_id' })) {
                # Add $Fields from Get-FalconHost, excluding 'device_id' (already present as 'aid')
                $Result.PSObject.Properties.Add((New-Object PSNoteProperty($Property.Name,$Property.Value)))
            }
        }
    }
    # Re-export CSV with added fields
    $CSV | Export-Csv -Path $ExportName -NoTypeInformation -Force
} else {
    throw "No vulnerabilities created within the last $Days days"
}