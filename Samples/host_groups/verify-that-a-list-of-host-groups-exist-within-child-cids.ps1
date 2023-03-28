#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Authenticate with each member CID, check for the presence of one or more host groups and output results to CSV
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER MemberCid
Member CID, used when authenticating within a multi-CID environment ('Falcon Flight Control') [default: all]
.PARAMETER GroupName
Host group name
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(Mandatory,Position=2)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(Position=3)]
    [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
    [string]$Cloud,
    [Parameter(Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$MemberCid,
    [Parameter(Mandatory,Position=5)]
    [string[]]$GroupName
)
begin {
    $Token = @{}
    @('ClientId','ClientSecret','Cloud').foreach{
        if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
    }
    if (!$MemberCid) {
        Request-FalconToken @Token
        if ((Test-FalconToken).Token -eq $true) {
            # Gather available Member CIDs
            [string[]]$MemberCid = Get-FalconMemberCid -Detailed -All | Where-Object {
                $_.status -eq 'active' } | Select-Object -ExpandProperty child_cid
            Revoke-FalconToken
        }
    }
    # Log file name and output location
    [string]$OutputFile = Join-Path (Get-Location).Path "VerifyGroup_$(Get-Date -Format FileDateTime).csv"

}
process {
    foreach ($Cid in $MemberCid) {
        try {
            # Authenticate with Member CID
            Request-FalconToken @Token -MemberCid $Cid
            if ((Test-FalconToken).Token -eq $true) {
                # Get group information
                [object[]]$GroupList = for ($i=0; $i -lt ($GroupName | Measure-Object).Count; $i+=100) {
                    [string]$Filter = (@($GroupName[$i..($i + 99)]).foreach{
                        "name:'$(($_).ToLower())'"
                    }) -join ','
                    Get-FalconHostGroup -Filter $Filter -Detailed | Select-Object id,name
                }
                # Create output object
                $Output = [PSCustomObject]@{ Cid = $Cid }
                foreach ($Name in $GroupName) {
                    # Add each group name and id
                    [string]$Id = if ($GroupList.name -contains $Name) {
                        ($GroupList | Where-Object { $_.name -eq $Name }).id
                    } else {
                        $null
                    }
                    $Output.PSObject.Properties.Add((New-Object PSNoteProperty($Name,$Id)))
                }
                # Output to CSV
                $Output | Export-Csv -Path $OutputFile -NoTypeInformation -Append
                Write-Host "Successfully output host groups for cid '$Cid'."
            }
        } catch {
            Write-Error $_
        } finally {
            if ((Test-FalconToken).Token -eq $true) {
                # Remove authentication token and sleep to avoid rate limiting
                Revoke-FalconToken
                Start-Sleep -Seconds 5
            }
        }
    }
}
end { if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }}