#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Download your most recent successful Scheduled Report (or Search) execution results
#>
Get-FalconScheduledReport -Detailed -All | Where-Object { $_.last_execution } |
Select-Object -ExpandProperty last_execution | Where-Object { $_.status -eq 'DONE' -and $_.result_metadata } |
ForEach-Object {
    Receive-FalconScheduledReport -Id $_.id -Path (
        Join-Path (Get-Location).Path $_.result_metadata.report_file_name)
}