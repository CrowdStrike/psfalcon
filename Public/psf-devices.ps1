function Find-FalconDuplicate {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [array] $Hosts,

        [Parameter(Position = 2)]
        [ValidateSet('external_ip', 'local_ip', 'mac_address', 'os_version', 'platform_name', 'serial_number')]
        [string] $Filter
    )
    begin {
        function Group-Selection ($Object, $GroupBy) {
            ($Object | Group-Object $GroupBy).Where({ $_.Count -gt 1 -and $_.Name }).foreach{
                $_.Group | Sort-Object last_seen | Select-Object -First ($_.Count - 1)
            }
        }
        # Comparison criteria and required properties for host results
        $Criteria = @('cid', 'hostname')
        $Required = @('cid', 'device_id', 'first_seen', 'last_seen', 'hostname')
        if ($PSBoundParameters.Filter) {
            $Criteria += $PSBoundParameters.Filter
            $Required += $PSBoundParameters.Filter
        }
        # Create filter for excluding results with empty $Criteria values
        $FilterScript = { (($Criteria).foreach{ "`$_.$($_)" }) -join ' -and ' }
    }
    process {
        $HostArray = if (!$PSBoundParameters.Hosts) {
            # Retreive Host details
            Get-FalconHost -Detailed -All
        } else {
            $PSBoundParameters.Hosts
        }
        ($Required).foreach{
            if (($HostArray | Get-Member -MemberType NoteProperty).Name -notcontains $_) {
                # Verify required properties are present
                throw "Missing required property '$_'."
            }
        }
        # Group, sort and output result
        $Param = @{
            Object  = $HostArray | Select-Object $Required | Where-Object -FilterScript $FilterScript
            GroupBy = $Criteria
        }
        $Output = Group-Selection @Param
    }
    end {
        if ($Output) {
            $Output
        } else {
            Write-Warning "No duplicates found."
        }
    }
}