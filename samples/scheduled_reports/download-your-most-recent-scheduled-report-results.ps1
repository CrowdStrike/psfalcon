#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

#>
(Get-FalconScheduledReport -Detailed -All).last_execution | ForEach-Object {
    Receive-FalconScheduledReport -Id $_.id -Path "$($_.result_metadata.report_file_name)"
}