#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(Mandatory,Position=2)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(Mandatory,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$MemberCid,
    [Parameter(Position=4)]
    [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
    [string]$Cloud,
    [Parameter(Mandatory,Position=5)]
    [ValidateSet('DeviceControl','Firewall','Prevention','Response','SensorUpdate')]
    [string]$PolicyType,
    [Parameter(Mandatory,Position=6)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$PolicyId
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
    [string]$OutputFile = Join-Path (Get-Location).Path "$(
        $PolicyType)Assignment_$(Get-Date -Format FileDate).csv"
}
process {
    foreach ($Cid in $MemberCid) {
        try {
            # Authenticate with Member CID
            Request-FalconToken @Token -MemberCid $Cid
            if ((Test-FalconToken).Token -eq $true) {
                # Get policy information
                & "Get-Falcon$($PolicyType)Policy" -Id $PolicyId | Select-Object id,groups | ForEach-Object {
                    [PSCustomObject]@{
                        # Output with CID, policy id and assigned groups
                        Cid = $Cid
                        PolicyId = $_.id
                        Groups = $_.groups.id -join ', '
                    } | Export-Csv -Path $OutputFile -NoTypeInformation -Append
                }
                Write-Host "Output assigned host groups for CID '$Cid'."
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