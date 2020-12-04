function Find-Duplicate {
    <#
    .SYNOPSIS
        Lists potential duplicates from detailed 'Host' results
    .PARAMETER HOSTS
        Array of detailed 'Host' results
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Position = 1,
            Mandatory = $true)]
        [array] $Hosts
    )
    begin {
        $Criteria = @('device_id', 'hostname', 'first_seen', 'last_seen', 'mac_address')
        $InputFields = ($Hosts | Get-Member -MemberType NoteProperty).Name
        function Group-Selection ($Selection, $Criteria) {
            $Selection | Group-Object $Criteria | Where-Object { $_.count -gt 1 } |
            Select-Object -ExpandProperty Group | Group-Object $Criteria | ForEach-Object {
                $_.Group | Select-Object -First (($_.count) - 1)
            }
        }
    }
    process {
        try {
            ($Criteria).foreach{
                if ($InputFields -notcontains $_) {
                    throw "Input object does not contain '$_' field"
                }
            }
            $Param = @{
                Selection = $Hosts | Select-Object $Criteria
                Criteria = 'hostname'
            }
            $Duplicates = Group-Selection @Param 
            if ($Duplicates) {
                $Duplicates
            }
            else {
                Write-Warning "No duplicates found"
            }
        }
        catch {
            $_
        }
    }
}
