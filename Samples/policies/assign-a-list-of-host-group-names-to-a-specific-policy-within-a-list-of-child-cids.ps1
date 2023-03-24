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
    [Parameter(Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$MemberCid,
    [Parameter(Position=4)]
    [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
    [string]$Cloud,
    [Parameter(Mandatory,Position=5)]
    [string[]]$GroupName,
    [Parameter(Mandatory,Position=6)]
    [ValidateSet('DeviceControl','Firewall','Prevention','Response','SensorUpdate')]
    [string]$PolicyType,
    [Parameter(Mandatory,Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$PolicyId
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
    [string]$OutputFile = Join-Path (Get-Location).Path "AssignGroup_$(Get-Date -Format FileDateTime).log"

    function Write-LogEntry ([string]$Source,[string]$Message) {
        # Write output and add to log file
        "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss') $Source] $Message" | Tee-Object -FilePath $OutputFile -Append
    }
}
process {
    foreach ($Cid in $MemberCid) {
        try {
            # Authenticate with Member CID
            Request-FalconToken @Token -MemberCid $Cid
            if ((Test-FalconToken).Token -eq $true) {
                @($GroupName).foreach{
                    # Get Host Group Id
                    $GroupId = Get-FalconHostGroup -Filter "name:'$(($_).ToLower())'"
                    if ($GroupId) {
                        # Assign Host Group to policy
                        $InvokeCommand = "Invoke-Falcon$($PolicyType)PolicyAction"
                        $Param = @{ Name = 'add-host-group'; Id = $PolicyId; GroupId = $GroupId }
                        $Assigned = & $InvokeCommand @Param
                        $Message = if ($Assigned) {
                            "Assigned group $GroupId to $PolicyType policy '$($Assigned.id)' in CID '$Cid'."
                        } else {
                            "Failed to assign group $GroupId to $PolicyType policy '$PolicyId' in CID '$Cid'."
                        }
                        Write-LogEntry $InvokeCommand $Message
                    } else {
                        Write-LogEntry 'Get-FalconHostGroup' "No results for group name '$_' in CID '$Cid'."
                    }
                }
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
