#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

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
    } | Export-Csv -Path .\indicators.csv -NoTypeInformation -Append
}