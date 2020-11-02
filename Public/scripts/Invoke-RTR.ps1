function Invoke-RTR {
<#
.SYNOPSIS
    Start a Real-time Response session and execute a command
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'scripts/InvokeRTR')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('scripts/InvokeRTR')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            # Amount of seconds to wait between confirmation attempts for single-host commands
            $Sleep = 2

            # Maximum sleep time while waiting for confirmation of single-host commands
            $MaxSleep = 30

            # Count total number of HostIds
            $HostCount = ($PSBoundParameters.HostIds).count

            if ($PSBoundParameters.Command -match 'runscript' -and $PSBoundParameters.Timeout -and
            ($PSBoundParameters.Arguments -notmatch "-Timeout \d{2,3}")) {
                # If using runscript and a timeout was included, ensure it's added to the arguments
                $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"

                if ($HostCount -eq 1) {
                    # Update maximum sleep time to match timeout for single-host sessions
                    $MaxSleep = $PSBoundParameters.Timeout
                }
            }
            if ($PSBoundParameters.Arguments -and ($PSBoundParameters.Arguments -notmatch '^-')) {
                # Encapsulate arguments in quotes when they don't have an explicit parameter
                $PSBoundParameters.Arguments = "'$($PSBoundParameters.Arguments)'"
            }
            # Gather available Real-time Response commands
            @{ 
                Responder = 'real-time-response/RTR-ExecuteActiveResponderCommand'
                Admin = 'real-time-response/RTR-ExecuteAdminCommand'
            }.GetEnumerator().foreach{
                New-Variable -Name $_.Key -Value (($Falcon.Endpoint($_.Value)).Parameters |
                    Where-Object { $_.Dynamic -eq 'Command' }).Enum
            }
            # Define permission level
            $Permission = switch ($PSBoundParameters.Command) {
                { $Admin -contains $_ } { 'Admin' }
                { $Responder -contains $_ } { 'Responder' }
                default { $null }
            }
            # Define 'invoke' command
            $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and $HostCount -gt 1) {
                "Invoke-FalconBatchGet"
            } else {
                "Invoke-Falcon$($Permission)Command"
            }
            # Define 'confirm' command
            if ($HostCount -eq 1) {
                $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
            }
            function Set-Field ($Item, $Object) {
                foreach ($Field in $Object.psobject.properties) {
                    if ($Item.psobject.properties.name -contains $Field.name -or $Field.name -eq 'task_id') {
                        # Set field and value on [PSCustomObject] from result
                        $Value = if (($Field.value -is [object[]]) -and ($Field.value[0] -is [string])) {
                            # Add array values as [string]
                            $Field.value -join ', '
                        } elseif ($Field.value.code -and $Field.value.message) {
                            # Combine error values into [string]
                            "$($Field.value.code): $($Field.value.message)"
                        } else {
                            $Field.value
                        }
                        $Name = if ($Field.name -eq 'task_id') {
                            # Add 'task_id' as 'cloud_request_id'
                            'cloud_request_id'
                        } else {
                            $Field.name
                        }
                        # Set value for field in $Item
                        $Item.$Name = $Value
                    }
                }
            }
            function Show-Results ($HostIds) {
                # Create and output a [PSCustomObject] array of filtered results by HostId
                [array] $Output = ($HostIds).foreach{
                    [PSCustomObject] @{
                        aid = $_
                        session_id = $null
                        cloud_request_id = $null
                        complete = $false
                        stdout = $null
                        stderr = $null
                        errors = $null
                    }
                }
                if ($HostCount -eq 1) {
                    # Single-host results
                    @($Init, $Confirm).foreach{
                        foreach ($Resource in $_.resources) {
                            Set-Field $Output[0] $Resource
                        }
                    }
                } else {
                    # Multi-host results
                    @($Init, $Request).foreach{
                        if ($_.resources) {
                            foreach ($Resource in $_.resources) {
                                foreach ($Result in $Resource.psobject.properties) {
                                    Set-Field ($Output | Where-Object aid -eq $Result.name) $Result.value
                                }
                            }
                        } elseif ($_.combined.resources) {
                            foreach ($Resource in $_.combined.resources) {
                                foreach ($Result in $Resource.psobject.properties) {
                                    Set-Field ($Output | Where-Object aid -eq $Result.name) $Result.value
                                }
                            }
                        }
                    }
                }
                # Output array
                $Output | Format-List
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            try {
                # Define session initialization parameters
                if ($HostCount -eq 1) {
                    $Param = @{
                        # Use HostId for single hosts
                        HostId = $PSBoundParameters.HostIds[0]
                    }
                } else {
                    $Param = @{
                        # Use HostIds for multiple hosts
                        HostIds = $PSBoundParameters.HostIds
                    }
                    if ($PSBoundParameters.Timeout) {
                        # Add timeout value
                        $Param['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                if ($PSBoundParameters.QueueOffline) {
                    # Add QueueOffline status
                    $Param['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                # Initialize session
                $Init = Start-FalconSession @Param

                # Define command request parameters
                if ($Init.batch_id) {
                    $Param = @{
                        # Use BatchId for batch sessions
                        BatchId = $Init.batch_id
                    }
                    if ($PSBoundParameters.Timeout) {
                        # Add timeout value
                        $Param['Timeout'] = $PSBoundParameters.Timeout
                    }
                } elseif ($Init.resources.session_id) {
                    $Param = @{
                        # Use SessionId for single hosts
                        SessionId = $Init.resources.session_id
                    }
                } else {
                    # Output error if session was not created
                    throw "$($Init.errors.code): $($Init.errors.message)"
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    # Use 'Arguments' as 'Path' for 'get' commands in batch sessions
                    $Param['Path'] = $PSBoundParameters.Arguments
                } else {
                    # Add command
                    $Param['Command'] = $PSBoundParameters.Command

                    if ($PSBoundParameters.Arguments) {
                        # Add arguments
                        $Param['Arguments'] = $PSBoundParameters.Arguments
                    }
                }
                # Send command request
                $Request = & $InvokeCmd @Param

                if ($Request.resources.cloud_request_id -and (-not $PSBoundParameters.QueueOffline)) {
                    # Define confirmation parameters for single-host commands
                    $Param = @{
                        CloudRequestId = $Request.resources.cloud_request_id
                        OutVariable = 'Confirm'
                    }
                    if ((& $ConfirmCmd @Param).resources.complete -eq $false) {
                        do {
                            if (-not $Confirm.resources) {
                                # Error when confirmation results are not retrieved
                                throw "$($Confirm.errors.code): $($Confirm.errors.message)"
                            }
                            Start-Sleep -Seconds $Sleep

                            $i += $Sleep
                        } until (
                            # Repeat confirmation requests until command has completed or $MaxSleep is reached
                            ((& $ConfirmCmd @Param).resources.complete -eq $true) -or ($i -ge $MaxSleep)
                        )
                    }
                } elseif ((-not $Request.combined.resources) -and (-not $Request.resources)) {
                    # Output error if command request failed
                    throw "$($Request.errors.code): $($Request.errors.message)"
                }
                # Output results
                Show-Results $PSBoundParameters.HostIds
           } catch {
                # Output error
                Write-Error "$($_.Exception.Message)"
            }
        }
    }
}