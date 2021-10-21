function Add-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [array] $Tags,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 3)]
        [boolean] $QueueOffline
    )
    begin {
        $Scripts = @{
            Linux   = 'IFS=, read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping ' +
                'tags are not set//; s/^tags=//; s/.$//"),$1" && IFS=$"\n" uniq=($(printf "%s\n" ${tag[*]} | sor' +
                't -u | xargs)) && uniq="$(echo ${uniq[*]} | tr " " ",")" && /opt/CrowdStrike/falconctl -d -f --' +
                'tags && /opt/CrowdStrike/falconctl -s --tags="$uniq" && /opt/CrowdStrike/falconctl -g --tags | ' +
                'sed "s/^Sensor grouping tags are not set//; s/^tags=//; s/.$//"'
            Mac     = 'echo "not_supported_in_psfalcon"'
            Windows = '$Key = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e' +
                '0423f-7058-48c9-a204-725362b67639}\Default"; $Tags = (reg query $Key) -match "GroupingTags"; $V' +
                'alue = if ($Tags) { ($Tags.Split("REG_SZ")[-1].Trim().Split(",") + $args.Split(",") | Select-Ob' +
                'ject -Unique) -join "," } else { $args }; [void] (reg add $Key /v GroupingTags /d $Value /f); W' +
                'rite-Output "$(((reg query $Key) -match "GroupingTags").Split("REG_SZ")[-1].Trim())"'
        }
    }
    process {
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object cid, device_id, platform_name
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                $CmdParam = @{
                    # Send 'runscript' with tag values
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '``` -CommandLine="' +
                        ($PSBoundParameters.Tags -join ',') + '"'
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
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
function Get-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 2)]
        [boolean] $QueueOffline
    )
    begin {
        $Scripts = @{
            Linux = "/opt/CrowdStrike/falconctl -g --tags | sed 's/^Sensor grouping tags are not set.//; s/^tags" +
                "=//; s/.$//'"
            Mac     = "/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed 's/^No grou" +
                "ping tags set//; s/^Grouping tags: //'"
            Windows = '$Tags = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c0' +
                '34b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -match "GroupingTags"; if ($Tags) { Wr' +
                'ite-Output "$($Tags.Split("REG_SZ")[-1].Trim())" }'
        }
    }
    process {
        
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object cid, device_id, platform_name
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                # Send 'runscript'
                $CmdParam = @{
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '```'
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
function Remove-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [array] $Tags,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 3)]
        [boolean] $QueueOffline
    )
    begin {
        $Scripts = @{
            Linux   = 'IFS=, && read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tag' +
                's | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"; if [[ ${tag[@]} ]]; the' +
                'n /opt/CrowdStrike/falconctl -d -f --tags && for i in ${del[@]}; do tag=(${tag[@]/$i}); done &&' +
                'IFS=$"\n" && val=($(printf "%s\n" ${tag[*]} | xargs)) && val="$(echo ${val[*]} | tr " " ",")" &' +
                '& /opt/CrowdStrike/falconctl -s --tags="$val"; fi; /opt/CrowdStrike/falconctl -g --tags | sed "' +
                's/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//"'
            Mac     = 'echo "not_supported_in_psfalcon"'
            Windows = '$Key = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e' +
                '0423f-7058-48c9-a204-725362b67639}\Default"; $Tags = (reg query $Key) -match "GroupingTags"; if' +
                ' ($Tags) { $Delete = $args.Split(","); $Value = $Tags.Split("REG_SZ")[-1].Trim().Split(",").Whe' +
                're({ $Delete -notcontains $_ }) -join ","; if ($Value) { [void] (reg add $Key /v GroupingTags /' +
                'd $Value /f) } else { [void] (reg delete $Key /v GroupingTags /f) }}; $Tags = (reg query $Key) ' +
                '-match "GroupingTags"; if ($Tags) { $Tags.Split("REG_SZ")[-1].Trim() }'
        }
    }
    process {
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object cid, device_id, platform_name
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                $CmdParam = @{
                    # Send 'runscript' with tag values
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '``` -CommandLine="' +
                        ($PSBoundParameters.Tags -join ',') + '"'
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
function Uninstall-FalconSensor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 2)]
        [boolean] $QueueOffline
    )
    begin {
        $Scripts = @{
            Linux   = 'echo "not_supported_in_psfalcon"'
            Mac     = 'echo "not_supported_in_psfalcon"'
            Windows = 'Start-Sleep -Seconds 5; $RegPath = if ((Get-WmiObject win32_operatingsystem).osar' +
                'chitecture -eq "64-bit") { "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion' +
                '\Uninstall" } else { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }; if ' +
                '(Test-Path $RegPath) { $RegKey = Get-ChildItem $RegPath | Where-Object { $_.GetValue("D' +
                'isplayName") -like "*CrowdStrike Windows Sensor*" }; if ($RegKey) { $UninstallString = ' +
                '$RegKey.GetValue("QuietUninstallString"); $Arguments = @("/c", $UninstallString); if ($' +
                'args) { $Arguments += "MAINTENANCE_TOKEN=$args" }; $ArgumentList = $Arguments -join " "' +
                '; Start-Process -FilePath cmd.exe -ArgumentList $ArgumentList -PassThru | Select-Object' +
                ' Id, ProcessName | ForEach-Object { Write-Output "$($_ | ConvertTo-Json -Compress)" }}}' +
                ' else { Write-Error "Unable to locate $RegPath" }'
        }
    }
    process {
        try {
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object cid, device_id,
                platform_name, device_policies
            $IdValue = switch ($HostInfo.device_policies.sensor_update.uninstall_protection) {
                'ENABLED'          { $HostInfo.device_id }
                'MAINTENANCE_MODE' { 'MAINTENANCE' }
            }
            $Token = if ($IdValue) {
                (Get-FalconUninstallToken -DeviceId $IdValue -AuditMessage (
                    "Uninstall-FalconSensor [$((Show-FalconModule).UserAgent)]")).uninstall_token
            }
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline -eq $true) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            if ($Init.session_id) {
                $CmdParam = @{
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '```'
                }
                if ($Token) {
                    $CmdParam.Arguments += " -CommandLine='$Token'"
                }
                $Request = Invoke-FalconAdminCommand @CmdParam
                if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                    do {
                        Start-Sleep -Seconds 5
                        $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                    } until (
                        $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                    )
                    @($HostInfo | Select-Object cid, device_id).foreach{
                        $Status = if ($Confirm.stdout) {
                            @($Confirm.stdout | ConvertFrom-Json).foreach{
                                "[$($_.Id)] '$($_.ProcessName)' started removal of the Falcon sensor"
                            }
                        } else {
                            $Confirm.stderr
                        }
                        Add-Property -Object $_ -Name 'status' -Value $Status
                        $_
                    }
                } else {
                    $Request
                }
            }
        } catch {
            throw $_
        }
    }
}