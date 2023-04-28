#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Output a list of vulnerabilities and include additional Host fields
.PARAMETER Days
Output vulnerabilities created within the last X days [default: 7]
.PARAMETER Fields
The list of fields to include [default: last_seen,mac_address,serial_number,external_ip]
.NOTES
A CSV will be created in your local directory named "Vunerabilities_<date_range>.csv"
#>
param(
    [Parameter(Position=1)]
    [int]$Days,
    [Parameter(Position=2)]
    [string[]]$Fields
)
# Force 'device_id' as a field to be used for matching results and set export filename
if (!$Days) { $Days = 7 }
if (!$Fields) { $Fields =  'last_seen','mac_address','serial_number','external_ip' }
if ($Fields -notcontains 'device_id') { $Fields += ,'device_id' }
$OutputFile = Join-Path (Get-Location).Path "Vulnerabilities_$(
    (Get-Date).AddDays(-$Days).ToString('yyyyMMdd'))_to_$(Get-Date -Format FileDate).csv"

# Gather vulnerabilities within date range (default: last 7 days) and export to CSV
$Param = @{
    Filter = "created_timestamp:>'last $Days days'"
    Detailed = $true
    All = $true
    Verbose = $true
}
Get-FalconVulnerability @Param | Export-FalconReport -Path $OutputFile
if (Test-Path $OutputFile) {
    # Import newly created vulnerability report
    $CSV = Import-Csv -Path $OutputFile
    if ($CSV) {
        # Gather host detail and append to CSV
        $HostInfo = $CSV | Select-Object -ExpandProperty aid | Get-FalconHost -Verbose | Select-Object $Fields
        foreach ($Item in $HostInfo) {
            foreach ($Result in ($CSV | Where-Object { $_.aid -eq $Item.device_id })) {
                foreach ($Property in ($Item.PSObject.Properties | Where-Object { $_.Name -ne 'device_id' })) {
                    # Add $Fields from Get-FalconHost, excluding 'device_id' (already present as 'aid')
                    $Result.PSObject.Properties.Add((New-Object PSNoteProperty($Property.Name,$Property.Value)))
                }
            }
        }
        # Re-export CSV with added fields
        $CSV | Export-Csv -Path $OutputFile -NoTypeInformation -Force
    }
} else {
    throw "No vulnerabilities created within the last $Days days"
}