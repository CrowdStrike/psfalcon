function Get-Queue {
<#
.SYNOPSIS
    Create a report of with status of queued Real-time Response sessions
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'CustomGetQueue')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('CustomGetQueue')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Retrieve 7 days worth of results if not otherwise specified
        $Days = if (-not $PSBoundParameters.Days) {
            7
        } else {
            $PSBoundParameters.Days
        }
        # Set file date for output
        $FileDateTime = Get-Date -Format FileDateTime

        # Output CSV filename
        $OutputFile = "$pwd\FalconQueue_$FileDateTime.csv"

        if ($PSBoundParameters.Debug -eq $true) {
            # Filename for debug logging
            $LogFile = "$pwd\FalconQueue_$FileDateTime.log"
        }
        # Commands and required permission levels
        $RequiresResponder = @('cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg delete',
        'reg load', 'reg set', 'reg unload', 'restart', 'rm', 'runscript', 'shutdown', 'umount', 'unmap',
        'xmemdump', 'zip')
        $RequiresAdmin = @('put', 'run')

        function Add-Field ($Object, $Name, $Value) {
            # Add NoteProperty to PSCustomObject
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Write-Log ($Value) {
            # Output timestamped message to console
            Write-Host "[$($Falcon.Rfc3339(0))] $Value"
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            try {
                # Make request for sessions with queued commands
                $Param = @{
                    Filter = "created_at:>'$($Falcon.Rfc3339(-$Days))'+commands_queued:1"
                    # All = $true TODO: fix this... all seems to break everything?
                }
                $SessionIds = Get-FalconSession @Param

                if ($PSBoundParameters.Debug -eq $true -and $SessionIds) {
                    # Capture full response in $LogFile
                    "SessionIds:`n $($SessionIds | ConvertTo-Json -Depth 8)`n" | Out-File $LogFile -Append
                }
                if ($SessionIds.resources) {
                    Write-Log "Found $($SessionIds.resources.count) session(s) with queued commands..."

                    # Retrieve detail about sessions with queued commands
                    $Param = @{
                        Queue = $true
                        SessionIds = $SessionIds.resources
                    }
                    $Sessions = Get-FalconSession @Param

                    if ($PSBoundParameters.Debug -eq $true -and $Sessions) {
                        # Capture full response in $LogFile
                        "Sessions:`n $($Sessions | ConvertTo-Json -Depth 8)`n" | Out-File $LogFile -Append
                    }
                } elseif ($SessionIds.errors) {
                    # Output error when unable to retrieve session identifiers
                    throw ("$($SessionIds.errors.code): $($SessionIds.errors.message)" +
                    " [$($SessionIds.meta.trace_id)]")
                } else {
                    # Output error if no results are available
                    throw "No queued sessions created within the last $($Days) day(s)"
                }
                if ($Sessions.resources) {
                    foreach ($Session in $Sessions.resources) {
                        ($Session.Commands).foreach{
                            # Create object for each command with common session fields
                            $Object = [PSCustomObject] @{
                                aid = $Session.aid
                                user_id = $Session.user_id
                                user_uuid = $Session.user_uuid
                                session_id = $Session.id
                                session_created_at = [datetime] $Session.created_at
                                session_deleted_at = if ($Session.deleted_at) {
                                    [datetime] $Session.deleted_at
                                } else {
                                    $null
                                }
                                session_updated_at = [datetime] $Session.updated_at
                                session_status = $Session.status
                                command_complete = $false
                                command_stdout = $null
                                command_stderr = $null
                            }
                            ($_.psobject.properties).foreach{
                                if ($_.name -eq 'status') {
                                    # Add 'status' with 'command' prefix
                                    Add-Field $Object "command_$($_.name)" $_.value
                                } elseif ($_.name -match '(created_at|updated_at|deleted_at)') {
                                    # Add date fields with 'command' prefix as [datetime]
                                    if ($_.value) {
                                        Add-Field $Object "command_$($_.name)" ([datetime] $_.value)
                                    } else {
                                        Add-Field $Object "command_$($_.name)" $null
                                    }
                                } else {
                                    Add-Field $Object $_.name $_.value
                                }
                            }
                            if ($Object.command_status -eq 'FINISHED') {
                                # Set permission from 'base_command'
                                $Permission = if ($RequiresAdmin -contains $Object.base_command) {
                                    'Admin'
                                } elseif ($RequiresResponder -contains $Object.base_command) {
                                    'Responder'
                                } else {
                                    $null
                                }
                                # Gather stdout/stderr from 'FINISHED' commands
                                $Param = @{
                                    CloudRequestId = $Object.cloud_request_id
                                    ErrorAction = 'SilentlyContinue'
                                }
                                $CmdResult = & "Confirm-Falcon$($Permission)Command" @Param

                                if ($PSBoundParameters.Debug -eq $true -and $CmdResult) {
                                    # Capture full response in $LogFile
                                    "CmdResult:`n $($CmdResult | ConvertTo-Json -Depth 8)`n" |
                                    Out-File $LogFile -Append
                                }
                                if ($CmdResult.resources) {
                                    Write-Log "Capturing cloud_request_id $($Object.cloud_request_id)..."

                                    (($CmdResult.resources | Select-Object stdout, stderr,
                                    complete).psobject.properties).foreach{
                                        # Update object with complete, stderr and stdout results
                                        $Object."command_$($_.Name)" = $_.Value
                                    }
                                }
                            }
                            # Output object to CSV
                            $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                        }
                    }
                } elseif ($Sessions.errors) {
                    # Output error when unable to retrieve session details
                    throw ("$($Sessions.errors.code): $($Sessions.errors.message)" +
                    " [$($Sessions.meta.trace_id)]")
                }
            } catch {
                # Output error
                Write-Error "$($_.Exception.Message)"
            } finally {
                # Display created file(s)
                foreach ($Item in @($LogFile, $OutputFile)) {
                    if ($Item -and (Test-Path $Item)) {
                        Get-ChildItem $Item | Out-Host
                    }
                }
            }
        }
    }
}