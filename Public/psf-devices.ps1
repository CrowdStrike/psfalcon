function Find-FalconDuplicate {
<#
.SYNOPSIS
Find potential duplicate hosts within your Falcon environment
.DESCRIPTION
Requires 'Hosts: Read' and 'Hosts: Write'.

If the 'Hosts' parameter is not provided, all Host information will be retrieved. An error will be
displayed if required fields 'cid', 'device_id', 'first_seen', 'last_seen', 'hostname' and any defined
'filter' value are not present.

Hosts are grouped by 'cid', 'hostname' and any defined 'filter' values, then sorted by 'last_seen' time. Any
result other than the one with the most recent 'last_seen' time is considered a duplicate host and is returned
within the output.

Hosts can be hidden from the Falcon console by piping the results of 'Find-FalconDuplicate' to
'Invoke-FalconHostAction' using the action 'hide_host'.
.PARAMETER Hosts
Array of detailed Host results
.PARAMETER Filter
Property to determine duplicate Host in addition to 'Hostname'
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Host-and-Host-Group-Management
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position=1)]
        [object[]]$Hosts,
        [Parameter(Position=2)]
        [ValidateSet('external_ip','local_ip','mac_address','os_version','platform_name','serial_number',
            IgnoreCase=$false)]
        [string[]]$Filter
    )
    begin {
        function Group-Selection ($Object,$GroupBy) {
            ($Object | Group-Object $GroupBy).Where({ $_.Count -gt 1 -and $_.Name }).foreach{
                $_.Group | Sort-Object last_seen | Select-Object -First ($_.Count - 1)
            }
        }
        # Comparison criteria and required properties for host results
        [string[]]$Criteria = 'cid','hostname'
        [string[]]$Required = 'cid','device_id','first_seen','last_seen','hostname'
        if ($PSBoundParameters.Filter) {
            $Criteria = $Criteria + $PSBoundParameters.Filter
            $Required = $Required + $PSBoundParameters.Filter
        }
        # Create filter for excluding results with empty $Criteria values
        $FilterScript = "$(($Criteria).foreach{ "`$_.$($_)" } -join ' -and ')"
    }
    process {
        [object[]]$HostArray = if (!$PSBoundParameters.Hosts) {
            # Retreive Host details
            Get-FalconHost -Detailed -All
        } else {
            $PSBoundParameters.Hosts
        }
        if ($HostArray) {
            @($Required).foreach{
                if (($HostArray | Get-Member -MemberType NoteProperty).Name -notcontains $_) {
                    # Verify required properties are present
                    throw "Missing required property '$_'."
                }
            }
            # Group, sort and output result
            $Param = @{
                Object = $HostArray | Select-Object $Required | Where-Object -FilterScript {$FilterScript}
                GroupBy = $Criteria
            }
            $Output = Group-Selection @Param
            if ($Output) { $Output } else { Write-Warning "No duplicates found." }
        }
    }
}