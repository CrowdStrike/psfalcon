function Invoke-RTR {
<#
.SYNOPSIS
    Creates a session, issues a Real-time Response command and confirms completion
.PARAMETER HOSTID
    Host identifier
.PARAMETER COMMAND
    Real-time Response command
.PARAMETER ARGUMENTS
    Arguments to include with the command
.PARAMETER QUEUEOFFLINE
    Add session to the offline queue if the host does not initialize
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('\w{32}')]
        [string] $HostId,

        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter()]
        [string] $Arguments,

        [Parameter()]
        [bool] $QueueOffline
    )
    begin {
        # Amount of seconds to wait between confirmation attempts
        $Sleep = 5

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
        $Permission = if ($AdminCmd -contains $Command) {
            'Admin'
        } elseif ($ResponderCmd -contains $Command) {
            'Responder'
        } else {
            $null
        }
    }
    process {
        try {
            # Create session
            $Param = @{
                HostId = $HostId
            }
            if ($QueueOffline) {
                $Param['QueueOffline'] = $QueueOffline
            }
            $Init = Start-FalconSession @Param

            if (-not $Init.resources.session_id) {
                # Error when session creation fails
                throw "$($Init.errors.code): $($Init.errors.message)"
            }
            # Submit command request
            $Param = @{
                SessionId = $Init.resources.session_id
                Command = $Command
            }
            if ($Arguments) {
                $Param['Arguments'] = $Arguments
            }
            $Request = & "Invoke-Falcon$($Permission)Command" @Param

            if (-not $Request.resources.cloud_request_id) {
                # Error when cloud_request_id is missing
                throw "$($Request.errors.code): $($Request.errors.message)"
            }
            if ($QueueOffline -and $Request.resources) {
                # Output result for queued session
                $Request.resources
            } elseif (-not $QueueOffline) {
                Start-Sleep -Seconds $Sleep

                # Query command results
                $Param = @{
                    CloudRequestId = $Request.resources.cloud_request_id
                }
                $Confirm = Confirm-FalconCommand @Param

                if (-not $Confirm.resources) {
                    # Error when confirmation results are not retrieved
                    throw "$($Confirm.errors.code): $($Confirm.errors.message)"
                } elseif ($Confirm.resources.complete -eq $false) {
                    do {
                        if (-not $Confirm.resources) {
                            # Error when confirmation results are not retrieved
                            throw "$($Confirm.errors.code): $($Confirm.errors.message)"
                        }
                        Start-Sleep -Seconds $Sleep
                    } until (
                        # Repeat requests until command has completed
                        (Confirm-FalconCommand @Param -OutVariable Confirm).resources.complete -eq $true
                    )
                }
                if ($Confirm.resources) {
                    Write-Debug ("[$($MyInvocation.MyCommand.Name)] $($Confirm.resources |
                    ConvertTo-Json -Depth 8)")
                }
                # Output 'stdout' or 'stderr' result
                if ($Confirm.resources.stdout) {
                    $Confirm.resources.stdout
                } elseif ($Confirm.resources.stderr) {
                    $Confirm.resources.stderr
                }
            }
        } catch {
            # Output error
            Write-Error "$($_.Exception.Message)"
        }
    }
}