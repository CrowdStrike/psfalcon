#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create a CSV containing 'ip_address' and 'domain' indicators created by CrowdStrike Threat Intelligence within
the last 7 days
.NOTES
The script will create 'indicators.csv' in your current directory
#>
$UnixDate = [DateTimeOffset]::Now.AddDays(-7).ToUnixTimeSeconds()
$Param = @{
    Filter = "(type:'ip_address',type:'domain')+last_updated:>$UnixDate"
    Detailed = $true
    All = $true
}
Get-FalconIndicator @Param | Select-Object indicator,type,malicious_confidence,labels | ForEach-Object {
    [PSCustomObject]@{
        value = $_.indicator
        type = $_.type
        confidence = $_.malicious_confidence
        comment = "$(($_.Labels.name | Where-Object { $_ -notmatch 'MaliciousConfidence/*' }) -join ', ')"
    } | Export-Csv -Path (Join-Path (Get-Location).Path 'indicators.csv') -NoTypeInformation -Append
}