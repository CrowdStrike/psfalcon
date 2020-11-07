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
        $Endpoints = @('scripts/InvokeRTR')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            $Sleep = 2
            $MaxSleep = 30
            $HostCount = ($PSBoundParameters.HostIds).count
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
            $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and $HostCount -gt 1) {
                "Invoke-FalconBatchGet"
            }
            else {
                "Invoke-Falcon$($Permission)Command"
            }
            if ($HostCount -eq 1) {
                $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
            }
            function Set-Field ($Item, $Object) {
                foreach ($Field in $Object.psobject.properties) {
                    if ($Item.psobject.properties.name -contains $Field.name -or $Field.name -eq 'task_id') {
                        $Value = if (($Field.value -is [object[]]) -and ($Field.value[0] -is [string])) {
                            $Field.value -join ', '
                        }
                        elseif ($Field.value.code -and $Field.value.message) {
                            "$($Field.value.code): $($Field.value.message)"
                        }
                        else {
                            $Field.value
                        }
                        $Name = if ($Field.name -eq 'task_id') {
                            'cloud_request_id'
                        }
                        else {
                            $Field.name
                        }
                        $Item.$Name = $Value
                    }
                }
            }
            function Show-Results ($HostIds) {
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
                    @($Init, $Confirm).foreach{
                        foreach ($Resource in $_.resources) {
                            Set-Field $Output[0] $Resource
                        }
                    }
                }
                else {
                    @($Init, $Request).foreach{
                        if ($_.resources) {
                            foreach ($Resource in $_.resources) {
                                foreach ($Result in $Resource.psobject.properties) {
                                    Set-Field ($Output | Where-Object aid -EQ $Result.name) $Result.value
                                }
                            }
                        }
                        elseif ($_.combined.resources) {
                            foreach ($Resource in $_.combined.resources) {
                                foreach ($Result in $Resource.psobject.properties) {
                                    Set-Field ($Output | Where-Object aid -EQ $Result.name) $Result.value
                                }
                            }
                        }
                    }
                }
                $Output | Format-List
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            try {
                if ($HostCount -eq 1) {
                    $Param = @{
                        HostId = $PSBoundParameters.HostIds[0]
                    }
                }
                else {
                    $Param = @{
                        HostIds = $PSBoundParameters.HostIds
                    }
                    if ($PSBoundParameters.Timeout) {
                        $Param['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                if ($PSBoundParameters.QueueOffline) {
                    $Param['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                $Init = Start-FalconSession @Param
                if ($Init.batch_id) {
                    $Param = @{
                        BatchId = $Init.batch_id
                    }
                    if ($PSBoundParameters.Timeout) {
                        $Param['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                elseif ($Init.resources.session_id) {
                    $Param = @{
                        SessionId = $Init.resources.session_id
                    }
                }
                else {
                    throw "$($Init.errors.code): $($Init.errors.message)"
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $Param['Path'] = $PSBoundParameters.Arguments
                }
                else {
                    $Param['Command'] = $PSBoundParameters.Command
                    if ($PSBoundParameters.Arguments) {
                        $Param['Arguments'] = $PSBoundParameters.Arguments
                    }
                }
                $Request = & $InvokeCmd @Param
                if ($Request.resources.cloud_request_id -and (-not $PSBoundParameters.QueueOffline)) {
                    $Param = @{
                        CloudRequestId = $Request.resources.cloud_request_id
                        OutVariable = 'Confirm'
                    }
                    if ((& $ConfirmCmd @Param).resources.complete -eq $false) {
                        do {
                            if (-not $Confirm.resources) {
                                throw "$($Confirm.errors.code): $($Confirm.errors.message)"
                            }
                            Start-Sleep -Seconds $Sleep
                            $i += $Sleep
                        } until (
                            ((& $ConfirmCmd @Param).resources.complete -eq $true) -or ($i -ge $MaxSleep)
                        )
                    }
                }
                elseif ((-not $Request.combined.resources) -and (-not $Request.resources)) {
                    throw "$($Request.errors.code): $($Request.errors.message)"
                }
                Show-Results $PSBoundParameters.HostIds
            }
            catch {
                Write-Error "$($_.Exception.Message)"
            }
        }
    }
}