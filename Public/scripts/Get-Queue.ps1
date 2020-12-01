function Get-Queue {
    <#
    .SYNOPSIS
        Create a report of with status of queued Real-time Response sessions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/GetQueue')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/GetQueue')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Days = if (-not $PSBoundParameters.Days) {
            7
        }
        else {
            $PSBoundParameters.Days
        }
        $FileDateTime = Get-Date -Format FileDateTime
        $OutputFile = "$pwd\FalconQueue_$FileDateTime.csv"
        $RequiresResponder = @('cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg delete',
            'reg load', 'reg set', 'reg unload', 'restart', 'rm', 'runscript', 'shutdown', 'umount', 'unmap',
            'xmemdump', 'zip')
        $RequiresAdmin = @('put', 'run')
        function Add-Field ($Object, $Name, $Value) {
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            try {
                $Param = @{
                    Filter = "(deleted_at:null+commands_queued:1),(created_at:>'Last $Days days'+" +
                    "commands_queued:1)"
                    All    = $true
                }
                $SessionIds = Get-FalconSession @Param
                if ($SessionIds) {
                    Write-Host "Found $($SessionIds.count) session(s) with queued commands..."
                    $Param = @{
                        Queue      = $true
                        SessionIds = $SessionIds
                    }
                    $Sessions = Get-FalconSession @Param
                }
                else {
                    throw "No queued sessions created within the last $($Days) day(s)"
                }
                foreach ($Session in $Sessions) {
                    ($Session.Commands).foreach{
                        $Object = [PSCustomObject] @{
                            aid                = $Session.aid
                            user_id            = $Session.user_id
                            user_uuid          = $Session.user_uuid
                            session_id         = $Session.id
                            session_created_at = [datetime] $Session.created_at
                            session_deleted_at = if ($Session.deleted_at) {
                                [datetime] $Session.deleted_at
                            }
                            else {
                                $null
                            }
                            session_updated_at = [datetime] $Session.updated_at
                            session_status     = $Session.status
                            command_complete   = $false
                            command_stdout     = $null
                            command_stderr     = $null
                        }
                        $Param = @{
                            Object = $Object
                        }
                        ($_.psobject.properties).foreach{
                            if ($_.name -eq 'status') {
                                Add-Field @Param -Name "command_$($_.name)" $_.value
                            }
                            elseif ($_.name -match '(created_at|updated_at|deleted_at)') {
                                $Value = if ($_.value) {
                                    [datetime] $_.value
                                }
                                else {
                                    $null
                                }
                                Add-Field @Param -Name "command_$($_.name)" -Value $Value
                            }
                            else {
                                Add-Field @Param -Name $_.name -Value $_.value
                            }
                        }
                        if ($Object.command_status -eq 'FINISHED') {
                            $Permission = if ($RequiresAdmin -contains $Object.base_command) {
                                'Admin'
                            }
                            elseif ($RequiresResponder -contains $Object.base_command) {
                                'Responder'
                            }
                            else {
                                $null
                            }
                            $Param = @{
                                CloudRequestId = $Object.cloud_request_id
                                ErrorAction    = 'SilentlyContinue'
                            }
                            $CmdResult = & "Confirm-Falcon$($Permission)Command" @Param
                            if ($CmdResult) {
                                Write-Host "Gathering results for $($Object.cloud_request_id)..."
                                (($CmdResult | Select-Object stdout, stderr,
                                complete).psobject.properties).foreach{
                                    $Object."command_$($_.Name)" = $_.Value
                                }
                            }
                        }
                        $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                    }
                }
            }
            catch {
                $_
            }
            finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile | Out-Host
                }
            }
        }
    }
}