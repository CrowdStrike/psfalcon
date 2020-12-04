function Find-Duplicate {
    <#
    .SYNOPSIS
        Lists potential duplicates from a detailed API result
    .PARAMETER HOSTS
        A detailed 'Hosts' API result
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
    process {
        if ($Hosts) {
            $InputData = $Hosts | Select-Object device_id, hostname, first_seen, last_seen, mac_address |
            Sort-Object last_seen
            $Criteria = 'hostname'
        }
        try {
            $Duplicates = if ($InputData -and $Criteria) {
                ($InputData | Group-Object $Criteria | Where-Object { $_.count -gt 1 } |
                Select-Object -ExpandProperty Group | Group-Object $Criteria) | ForEach-Object { $_.Group |
                Select-Object -First (($_.count) - 1) }
            }
            if ($Duplicates) {
                $Duplicates
            }
            else {
                Write-Host "No duplicates found"
            }
        }
        catch {
            $_
        }
    }
}
