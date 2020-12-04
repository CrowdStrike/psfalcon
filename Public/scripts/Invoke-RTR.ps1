function Invoke-RTR {
    <#
    .SYNOPSIS
        Start a Real-time Response session and execute a command
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/InvokeRTR')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/InvokeRTR')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            $MaxHosts = 500
            $Sleep = 2
            $MaxSleep = 30
            if ($PSBoundParameters.Command -match 'runscript' -and $PSBoundParameters.Timeout -and
                ($PSBoundParameters.Arguments -notmatch "-Timeout \d{2,3}")) {
                $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
                if ($HostCount -eq 1) {
                    $MaxSleep = $PSBoundParameters.Timeout
                }
            }
            if ($PSBoundParameters.Arguments -and ($PSBoundParameters.Arguments -notmatch '^-')) {
                $PSBoundParameters.Arguments = "'$($PSBoundParameters.Arguments)'"
            }
            @{
                Responder = 'real-time-response/RTR-ExecuteActiveResponderCommand'
                Admin = 'real-time-response/RTR-ExecuteAdminCommand'
            }.GetEnumerator().foreach{
                New-Variable -Name $_.Key -Value (($Falcon.Endpoint($_.Value)).Parameters |
                Where-Object { $_.Dynamic -eq 'Command' }).Enum
            }
            $Permission = switch ($PSBoundParameters.Command) {
                { $Admin -contains $_ } { 'Admin' }
                { $Responder -contains $_ } { 'Responder' }
                default { $null }
            }
            $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and $PSBoundParameters.HostIds.count -gt 1) {
                "Invoke-FalconBatchGet"
            }
            else {
                "Invoke-Falcon$($Permission)Command"
            }
            if ($PSBoundParameters.HostIds.count -eq 1) {
                $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
            }
            function Write-Result ($Object, $Item) {
                ($Object.PSObject.Properties).foreach{
                    $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
                        $_.Value -join ', '
                    }
                    elseif ($_.Value.code -and $_.Value.message) {
                        "$($_.Value.code): $($_.Value.message)"
                    }
                    else {
                        $_.Value
                    }
                    $Name = if ($_.Name -eq 'task_id') {
                        'cloud_request_id'
                    }
                    elseif ($_.Name -eq 'queued_command_offline') {
                        'offline_queued'
                    }
                    else {
                        $_.Name
                    }
                    if ($Item.PSObject.Properties.Name -contains $Name) {
                        $Item.$Name = $Value
                    }
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            for ($i = 0; $i -lt $PSBoundParameters.HostIds.count; $i += $MaxHosts) {
                try {
                    [array] $Output = ($PSBoundParameters.HostIds[$i..($i + ($MaxHosts - 1))]).foreach{
                        [PSCustomObject] @{
                            aid = $_
                            batch_id = $null
                            session_id = $null
                            cloud_request_id = $null
                            complete = $false
                            offline_queued = $false
                            stdout = $null
                            stderr = $null
                            errors = $null
                        }
                    }
                    $HostParam = if ($Output.aid.count -eq 1) {
                        $Output[0].PSObject.Properties.Remove('batch_id')
                        'HostId'
                    }
                    else {
                        'HostIds'
                    }
                    $Param = @{
                        $HostParam = $Output.aid
                    }
                    switch ($PSBoundParameters.Keys) {
                        'QueueOffline' {
                            $Param['QueueOffline'] = $PSBoundParameters.$_
                        }
                        'Timeout' {
                            if ($HostParam -eq 'HostIds') {
                                $Param['Timeout'] = $PSBoundParameters.$_
                            }
                        }
                    }
                    $Init = Start-FalconSession @Param
                    if ($Init) {
                        $Content = if ($Init.hosts) {
                            $Init.hosts
                        }
                        else {
                            $Init
                        }
                        foreach ($Result in $Content) {
                            $Item = ($Output | Where-Object { $_.aid -eq $Result.aid })
                            Write-Result -Object $Result -Item $Item
                            if (($PSBoundParameters.QueueOffline -eq $true -or $Result.session_id) -and
                            $Init.batch_id) {
                                $Item.batch_id = $Init.batch_id
                            } 
                        }
                        $SessionType = if ($HostParam -eq 'HostIds') {
                            'BatchId'
                            $IdValue = $Init.batch_id
                        }
                        else {
                            'SessionId'
                            $IdValue = $Init.session_id
                        }
                        $Param = @{
                            $SessionType = $IdValue
                        }
                        switch ($PSBoundParameters.Keys) {
                            'Command' {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                            'Arguments' {
                                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                                    $Param['Path'] = $PSBoundParameters.$_
                                }
                                else {
                                    $Param[$_] = $PSBoundParameters.$_
                                }
                            }
                            'Timeout' {
                                if ($SessionType -eq 'BatchId') {
                                    $Param[$_] = $PSBoundParameters.$_
                                }
                            }
                        }
                        $Request = & $InvokeCmd @Param
                    }
                    if ($Request -and $HostParam -eq 'HostIds') {
                        foreach ($Result in $Request) {
                            Write-Result -Object $Result -Item ($Output | Where-Object { $_.session_id -eq
                            $Result.session_id })
                        }
                        $Output
                    }
                    elseif ($Request) {
                        Write-Result -Object $Request -Item $Output[0]
                        if ($Output[0].cloud_request_id -and $Output[0].complete -eq $false -and
                        $Output[0].offline_queued -eq $false) {
                            do {
                                Start-Sleep -Seconds $Sleep
                                $Confirm = & $ConfirmCmd -CloudRequestId $Output[0].cloud_request_id
                                Write-Result -Object $Confirm -Item $Output[0]
                                $i += $Sleep
                            } until (
                                ($Output[0].complete -eq $true) -or ($i -ge $MaxSleep)
                            )
                        }
                        $Output
                    }
                }
                catch {
                    $_
                }
            }
        }
    }
}