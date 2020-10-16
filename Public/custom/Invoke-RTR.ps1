function Invoke-RTR {
<#
.SYNOPSIS
    Start a Real-time Response session and execute a command
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'InvokeRTR')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('InvokeRTR')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            # Amount of seconds to wait between confirmation attempts
            $Sleep = 2

            # Collect total HostId count for session or batch
            $HostCount = ($PSBoundParameters.HostIds.count)

            # Gather available commands and set permission level
            @{ 
                Responder = 'RTR-ExecuteActiveResponderCommand'
                Admin = 'RTR-ExecuteAdminCommand'
            }.GetEnumerator().foreach{
                New-Variable -Name $_.Key -Value (($Falcon.Endpoint($_.Value)).Parameters |
                    Where-Object { $_.Dynamic -eq 'Command' }).Enum
            }
            $Permission = switch ($PSBoundParameters.Command) {
                { $Admin -contains $_ } { 'Admin' }
                { $Responder -contains $_ } { 'Responder' }
                default { $null }
            }
            # Set 'invoke' command
            $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and $HostCount -gt 1) {
                "Invoke-FalconBatchGet"
            } else {
                "Invoke-Falcon$($Permission)Command"
            }
            # Set 'confirm' command
            if ($HostCount -eq 1) {
                $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
            }
            function Add-Field ($Object, $Name, $Value) {
                # Add field and value to [PSCustomObject]
                $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            try {
                if ($HostCount -eq 1) {
                    $Param = @{
                        HostId = [string] $PSBoundParameters.HostIds
                    }
                } else {
                    $Param = @{
                        HostIds = $PSBoundParameters.HostIds
                    }
                }
                switch ($PSBoundParameters.Keys) {
                    'Timeout' {
                        if ($HostCount -gt 1) {
                            $Param['Timeout'] = $PSBoundParameters.Timeout
                        }
                    }
                    'QueueOffline' {
                        $Param['QueueOffline'] = $PSBoundParameters.QueueOffline
                    }
                }
                $Init = Start-FalconSession @Param

                if ((-not $Init.resources.session_id) -and (-not $Init.batch_id)) {
                    # Error when session creation fails
                    throw "$($Init.errors.code): $($Init.errors.message)"
                }
                # Submit command request
                $Param = @{
                    Command = $PSBoundParameters.Command
                }
                if ($Init.batch_id) {
                    $Param['BatchId'] = $Init.batch_id
                } else {
                    $Param['SessionId'] = $Init.resources.session_id
                }
                if ($PSBoundParameters.Arguments) {
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                        $Param['Path'] = "'$($PSBoundParameters.Arguments)'"
                        $Param.Remove('Command')
                    } else {
                        $Param['Arguments'] = "'$($PSBoundParameters.Arguments)'"
                    }
                }
                $Request = & $InvokeCmd @Param

                if ((-not $Request.resources.cloud_request_id) -and (-not $Request.combined.resources)) {
                    # Error when command results are missing
                    throw "$($Request.errors.code): $($Request.errors.message)"
                }
                if ((-not $PSBoundParameters.QueueOffline) -and ($Request.resources)) {
                    Start-Sleep -Seconds $Sleep

                    # Query command results
                    $Param = @{
                        CloudRequestId = $Request.resources.cloud_request_id
                    }
                    $Confirm = & $ConfirmCmd @Param

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
                            (& $ConfirmCmd @Param -OutVariable Confirm).resources.complete -eq $true
                        )
                    }
                }
                # Create output array
                $Output = if ($Request.resources) {
                    $Item = [PSCustomObject] @{}

                    ($Request.resources).foreach{
                        ($_.PSObject.Properties).foreach{
                            # Add initial request results for individual sessions
                            Add-Field $Item $_.Name $_.Value
                        }
                    }
                    ($Confirm.resources | Select-Object base_command, complete, stdout, stderr).foreach{
                        ($_.PSObject.Properties).foreach{
                            if ($_.Value) {
                                # Add command detail
                                Add-Field $Item $_.Name $_.Value
                            }
                        }
                    }
                    # Add result to array
                    $Item
                } elseif ($Request.combined.resources) {
                    ($Init.resources.PSObject.Properties.Value | Where-Object { $_.complete -eq $false -and
                    $_.offline_queued -eq $false }).foreach{
                        $Item = [PSCustomObject] @{}

                        ($_.PSObject.Properties).foreach{
                            if ($_.Name -eq 'task_id') {
                                # Add 'task_id' as 'cloud_request_id'
                                Add-Field $Item 'cloud_request_id' $_.Value
                            } elseif ($_.Name -eq 'errors' -and $_.Value) {
                                $Value = if ($_.Value) {
                                    "$($_.Value.code): $($_.Value.message)"
                                } else {
                                    $null
                                }
                                # Combine error messages or add empty value
                                Add-Field $Item $_.Name $Value
                            } else {
                                Add-Field $Item $_.Name $_.Value
                            }
                        }
                        # Add result to array
                        $Item
                    }
                    ($Request.combined.resources.PSObject.Properties.Value).foreach{
                        $Item = [PSCustomObject] @{}

                        ($_.PSObject.Properties).foreach{
                            # Add results for batch sessions
                            if ($_.Name -eq 'task_id') {
                                # Add 'task_id' as 'cloud_request_id'
                                Add-Field $Item 'cloud_request_id' $_.Value
                            } elseif ($_.Name -eq 'errors') {
                                $Value = if ($_.Value) {
                                    "$($_.Value.code): $($_.Value.message)"
                                } else {
                                    $null
                                }
                                # Combine error messages or add empty value
                                Add-Field $Item $_.Name $Value
                            } else {
                                Add-Field $Item $_.Name $_.Value
                            }
                        }
                        # Add result to array
                        $Item
                    }
                }
                # Output result(s)
                $Output
            } catch {
                # Output error
                Write-Error "$($_.Exception.Message)"
            }
        }
    }
}