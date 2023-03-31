#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

#>
param(
    [Parameter(Mandatory,Position=1)]
    [string]$GroupName,
    [Parameter(Mandatory,Position=2)]
    [string]$Command,
    [Parameter(Position=3)]
    [string]$Arguments,
    [boolean]$QueueOffline
)
# Find group identifier using 'name' filter
$GroupId = Get-FalconHostGroup -Filter "name:'$($GroupName.ToLower())'"

if ($GroupId) {
    # Get host identifiers for members of $GroupId
    $Members = Get-FalconHostGroupMember -Id $GroupId -All
} else {
    throw "No host group found matching '$GroupName'"
}
if ($Members) {
    # Set filename for CSV export
    $ExportName = Join-Path (Get-Location).Path "$('rtr',($Command -replace ' ','_'),$GroupId -join '_').csv"

    # Set base parameters for Invoke-FalconRTR
    $Param = @{ Command = $Command; HostId = $Members }
    switch ($PSBoundParameters.Keys) {
        # Append parameters from user input that match Invoke-FalconRTR
        { $_ -ne 'GroupName' } { $Param[$_] = $PSBoundParameters.$_ }
    }
    # Issue command and export results to CSV
    Invoke-FalconRtr @Param | Export-Csv -Path $ExportName
    
    if (Test-Path $ExportName) {
        # Display CSV file
        Get-ChildItem $ExportName
    }
} else {
    throw "No members found in host group '$GroupName' [$GroupId]"
}