function Invoke-RTRBatch {
<#
.SYNOPSIS
    Creates a session, issues a Real-time Response command and confirms completion
.PARAMETER HOSTIDS
    Host identifiers
.PARAMETER COMMAND
    Real-time Response command
.PARAMETER ARGUMENTS
    Arguments to include with the command
.PARAMETER TIMEOUT
    Length of time to wait for a result, in seconds
.PARAMETER QUEUEOFFLINE
    Add sessions in this batch to the offline queue if the hosts do not initialize
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('\w{32}')]
        [array] $HostIds,

        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter()]
        [string] $Arguments,

        [Parameter()]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter()]
        [bool] $QueueOffline
    )
    begin {
        # Gather commands, sorted by permission level
        $ReadCmd = ($Falcon.Endpoint('CustomRTR').Parameters |
        Where-Object { $_.Dynamic -eq 'Command' }).Enum

        $ResponderCmd = ($Falcon.Endpoint('RTR-ExecuteActiveResponderCommand').Parameters |
        Where-Object { $_.Dynamic -eq 'Command' }).Enum | Where-Object { $_ -notin $ReadCmd }

        $AdminCmd = ($Falcon.Endpoint('RTR-ExecuteAdminCommand').Parameters |
        Where-Object { $_.Dynamic -eq 'Command' }).Enum | Where-Object { ($_ -notin $ReadCmd) -and
        ($_ -notin $ResponderCmd) }

        # Add 'runscript' to list of admin commands to avoid permission errors
        $AdminCmd += 'runscript'

        # Set permission level
        $Permission = if ($AdminCmd -contains $PSBoundParameters.Command) {
            'Admin'
        } elseif ($ResponderCmd -contains $PSBoundParameters.Command) {
            'Responder'
        } else {
            $null
        }
    }
    process {
        try {
            # Create session
            $Param = @{
                HostIds = $PSBoundParameters.HostIds
            }
            switch ($PSBoundParameters.Keys) {
                'Timeout' { $Param['Timeout'] = $PSBoundParameters.Timeout }
                'QueueOffline' { $Param['QueueOffline'] = $PSBoundParameters.QueueOffline }
            }
            $Init = Start-FalconSession @Param

            if (-not $Init.batch_id) {
                # Error when session creation fails
                throw "$($Init.errors.code): $($Init.errors.message)"
            }
            # Submit command request
            $Param = @{
                BatchId = $Init.batch_id
                Command = $PSBoundParameters.Command
            }
            switch ($PSBoundParameters.Keys) {
                'Arguments' { $Param['Arguments'] = $PSBoundParameters.Arguments }
                'Timeout' { $Param['Timeout'] = $PSBoundParameters.Timeout }
            }
            $Request = & "Invoke-Falcon$($Permission)Command" @Param

            if (-not $Request.combined.resources) {
                # Error when cloud_request_id is missing
                throw "$($Request.errors.code): $($Request.errors.message)"
            } else {
                # Output result
                $Request.combined.resources.psobject.properties.value
            }
        } catch {
            # Output error
            Write-Error "$($_.Exception.Message)"
        }
    }
}