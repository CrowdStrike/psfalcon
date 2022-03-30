function Add-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to add FalconSensorTags to hosts
.DESCRIPTION
Requires 'real-time-response-admin:write'.

Provided FalconSensorTag values will be appended to any existing tags.
.PARAMETER Tags
FalconSensorTag value
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Host-and-Host-Group-Management
#>
    [CmdletBinding(DefaultParameterSetName='HostId')]
    param(
        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [Parameter(ParameterSetName='HostIds',Mandatory,Position=1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [string[]]$Tags,

        #[Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,Position=2)]
        #[ValidatePattern('^\w{32}$')]
        #[Alias('device_id')]
        #[string]$Id,

        [Parameter(ParameterSetName='HostId',Position=3)]
        [Parameter(ParameterSetName='HostIds',Position=3)]
        [boolean]$QueueOffline,

        [Parameter(ParameterSetName='HostIds',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = 'IFS=,read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping ' +
                'tags are not set//; s/^tags=//; s/.$//"),$1" && IFS=$"\n" uniq=($(printf "%s\n" ${tag[*]} | sor' +
                't -u | xargs)) && uniq="$(echo ${uniq[*]} | tr " " ",")" && /opt/CrowdStrike/falconctl -d -f --' +
                'tags && /opt/CrowdStrike/falconctl -s --tags="$uniq" && /opt/CrowdStrike/falconctl -g --tags | ' +
                'sed "s/^Sensor grouping tags are not set//; s/^tags=//; s/.$//"'
            Mac = 'IFS=,tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | se' +
                'd "s/^No grouping tags set//; s/^Grouping tags: //")) tag+=($1) && uniq=$(echo "${tag[@]}" | tr' +
                ' " " "\n" | sort -u | tr "\n" "," | sed "s/,$//") && /Applications/Falcon.app/Contents/Resource' +
                's/falconctl grouping-tags clear &> /dev/null && /Applications/Falcon.app/Contents/Resources/fal' +
                'conctl grouping-tags set "$uniq" &> /dev/null && /Applications/Falcon.app/Contents/Resources/fa' +
                'lconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"'
            Windows = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e04' +
                '23f-7058-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags" | Where-Ob' +
                'ject { $_ }; $V = if ($T) { (($T -split "REG_SZ")[-1].Trim().Split(",") + $args.Split(",") | Se' +
                'lect-Object -Unique) -join "," } else { $args }; [void] (reg add $K /v GroupingTags /d $V /f); ' +
                '"$((((reg query $K) -match "GroupingTags") -split "REG_SZ")[-1].Trim())"'
        }
    }
    process {
        try {
            # Get device info to determine script and begin session
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                $InvokeParam = @{
                    HostId = $HostInfo.device_id
                    Command = 'runscript'
                    Argument = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '``` -CommandLine="' +
                        ($PSBoundParameters.Tags -join ',') + '"'
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                Invoke-FalconRtr @InvokeParam | ForEach-Object {
                    if ($PSBoundParameters.QueueOffline) {
                        # Output queued command result
                        $_
                    } else {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = $HostInfo.cid
                            device_id = $HostInfo.device_id
                            tags = if ($_.stdout) { ($_.stdout).Trim() } else { $_.stderr }
                        }
                    }
                }
            } else {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name) {
                    # Start sessions for each 'platform' type
                    $InvokeParam = @{
                        Command = 'runscript'
                        Argument =  '-Raw=```' + $Scripts.$Platform + '``` -CommandLine="' +
                            ($PSBoundParameters.Tags -join ',') + '"'
                        HostId = ($HostInfo | Where-Object { $_.platform_name -eq $Platform }).device_id
                    }
                    if ($PSBoundParameters.QueueOffline) {
                        $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                    }
                    Invoke-FalconRtr @InvokeParam | Select-Object aid,stdout,stderr,errors |
                    ForEach-Object {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = ($HostInfo | Where-Object device_id -eq $_.aid).cid
                            device_id = $_.aid
                            tags = if ($_.stdout) {
                                ($_.stdout).Trim()
                            } elseif ($_.stderr) {
                                $_.stderr
                            } else {
                                $_.errors
                            }
                        }
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}
function Get-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to display FalconSensorTags assigned to hosts
.DESCRIPTION
Requires 'real-time-response-admin:write'.
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Host-and-Host-Group-Management
#>
    [CmdletBinding(DefaultParameterSetName='HostId')]
    param(
        #[Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,Position=1)]
        #[ValidatePattern('^\w{32}$')]
        #[Alias('device_id')]
        #[string]$Id,

        [Parameter(ParameterSetName='HostId',Position=3)]
        [boolean]$QueueOffline,

        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = "/opt/CrowdStrike/falconctl -g --tags | sed 's/^Sensor grouping tags are not set.//; s/^tags" +
                "=//; s/.$//'"
            Mac = "/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed 's/^No grou" +
                "ping tags set//; s/^Grouping tags: //'"
            Windows = '$T = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b' +
                '88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -match "GroupingTags"; if ($T) { "$(($T -' +
                'split "REG_SZ")[-1].Trim())" }'
        }
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                $InvokeParam = @{
                    HostId = $HostInfo.device_id
                    Command = 'runscript'
                    Argument = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '```'
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                Invoke-FalconRtr @InvokeParam | ForEach-Object {
                    if ($PSBoundParameters.QueueOffline) {
                        # Output queued command result
                        $_
                    } else {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = $HostInfo.cid
                            device_id = $HostInfo.device_id
                            tags = if ($_.stdout) { ($_.stdout).Trim() } else { $_.stderr }
                        }
                    }
                }
            } else {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name) {
                    # Start session for each 'platform' type
                    $InvokeParam = @{
                        Command = 'runscript'
                        Argument =  '-Raw=```' + $Scripts.$Platform + '```'
                        HostId = ($HostInfo | Where-Object { $_.platform_name -eq $Platform }).device_id
                    }
                    if ($PSBoundParameters.QueueOffline) {
                        $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                    }
                    Invoke-FalconRtr @InvokeParam | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = ($HostInfo | Where-Object device_id -eq $_.aid).cid
                            device_id = $_.aid
                            tags = if ($_.stdout) {
                                ($_.stdout).Trim()
                            } elseif ($_.stderr) {
                                $_.stderr
                            } else {
                                $_.errors
                            }
                        }
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}
function Remove-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to remove FalconSensorTags from hosts
.DESCRIPTION
Requires 'real-time-response-admin:write'.
 Provided FalconSensorTag values will be removed from existing tags and others will be left unmodified.
.PARAMETER Tags
FalconSensorTag value
.PARAMETER Id
Host identifier
.PARAMETER QueueOffline
Add command request to the offline queue
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Host-and-Host-Group-Management
#>
    [CmdletBinding(DefaultParameterSetName='HostId')]
    param(
        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [Parameter(ParameterSetName='HostIds',Mandatory,Position=1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [string[]]$Tags,

        #[Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,Position=2)]
        #[ValidatePattern('^\w{32}$')]
        #[Alias('device_id')]
        #[string]$Id,

        [Parameter(ParameterSetName='HostId',Position=3)]
        [Parameter(ParameterSetName='HostIds',Position=3)]
        [boolean]$QueueOffline,

        [Parameter(ParameterSetName='HostIds',Mandatory,Position=2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = 'IFS=,&& read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tag' +
                's | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"; if [[ ${tag[@]} ]]; the' +
                'n /opt/CrowdStrike/falconctl -d -f --tags && for i in ${del[@]}; do tag=(${tag[@]/$i}); done &&' +
                'IFS=$"\n" && val=($(printf "%s\n" ${tag[*]} | xargs)) && val="$(echo ${val[*]} | tr " " ",")" &' +
                '& /opt/CrowdStrike/falconctl -s --tags="$val"; fi; /opt/CrowdStrike/falconctl -g --tags | sed "' +
                's/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//"'
            Mac = 'IFS=,tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | se' +
                'd "s/^No grouping tags set//; s/^Grouping tags: //")) del=("${(@s/,/)1}") && for i in ${del[@]}' +
                '; do tag=("${tag[@]/$i}"); done && tag=$(echo "${tag[@]}" | xargs | tr " " "," | sed "s/,$//") ' +
                '&& /Applications/Falcon.app/Contents/Resources/falconctl grouping-tags clear &> /dev/null && /A' +
                'pplications/Falcon.app/Contents/Resources/falconctl grouping-tags set "$tag" &> /dev/null && /A' +
                'pplications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tag' +
                's set//; s/^Grouping tags: //"'
            Windows = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e04' +
                '23f-7058-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags"; if ($T) {' +
                ' $D = $args.Split(","); $V = ($T -split "REG_SZ")[-1].Trim().Split(",").Where({ $D -notcontains' +
                ' $_ }) -join ","; if ($V) { [void] (reg add $K /v GroupingTags /d $V /f) } else { [void] (reg d' +
                'elete $K /v GroupingTags /f) }}; $T = (reg query $K) -match "GroupingTags"; if ($T) { ($T -spli' +
                't "REG_SZ")[-1].Trim() }'
        }
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                $InvokeParam = @{
                    HostId = $HostInfo.device_id
                    Command = 'runscript'
                    Argument = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '``` -CommandLine="' +
                        ($PSBoundParameters.Tags -join ',') + '"'
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                Invoke-FalconRtr @InvokeParam | ForEach-Object {
                    if ($PSBoundParameters.QueueOffline) {
                        # Output queued command result
                        $_
                    } else {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = $HostInfo.cid
                            device_id = $HostInfo.device_id
                            tags = if ($_.stdout) { ($_.stdout).Trim() } else { $_.stderr }
                        }
                    }
                }
            } else {
                $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,platform_name
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name) {
                    # Start session for each 'platform' type
                    $InvokeParam = @{
                        Command = 'runscript'
                        Argument =  '-Raw=```' + $Scripts.$Platform + '``` -CommandLine="' +
                            ($PSBoundParameters.Tags -join ',') + '"'
                        HostId = ($HostInfo | Where-Object { $_.platform_name -eq $Platform }).device_id
                    }
                    if ($PSBoundParameters.QueueOffline) {
                        $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                    }
                    Invoke-FalconRtr @InvokeParam | Select-Object aid,stdout,stderr,errors |
                    ForEach-Object {
                        # Output device properties and 'tags' value
                        [PSCustomObject] @{
                            cid = ($HostInfo | Where-Object device_id -eq $_.aid).cid
                            device_id = $_.aid
                            tags = if ($_.stdout) {
                                ($_.stdout).Trim()
                            } elseif ($_.stderr) {
                                $_.stderr
                            } else {
                                $_.errors
                            }
                        }
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}
function Uninstall-FalconSensor {
<#
.SYNOPSIS
Use Real-time Response to uninstall the Falcon sensor from a host
.DESCRIPTION
Requires 'devices:read','sensor-update-policies:write',and 'real-time-response-admin:write'.

This command uses information from the registry of the target host to uninstall the Falcon sensor. If the sensor
is damaged or malfunctioning,Real-time Response may not work properly and/or the uninstallation may not succeed.
.PARAMETER HostId
Host identifier
.PARAMETER QueueOffline
Add command request to the offline queue
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Host-and-Host-Group-Management
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string]$Id,

        [Parameter(Position=2)]
        [boolean]$QueueOffline
    )
    begin {
        $Scripts = @{
            Linux = 'manager=("$(if [[ $(command -v apt) ]]; then echo "apt-get purge falcon-sensor -y"; elif ' +
                '[[ $(command -v yum) ]]; then echo "yum remove falcon-sensor -y"; elif [[ $(command -v zypper) ' +
                ']]; then echo "zypper remove -y falcon-sensor"; fi)"); if [[ ${manager} ]]; then echo "Beginnin' +
                'g removal of the Falcon sensor" && eval "sudo ${manager} &" &>/dev/null; else echo "apt,yum or' +
                ' zypper must be present to begin removal"; fi'
            Mac = $null
            Windows = 'Start-Sleep -Seconds 5; $RegPath = if ((Get-WmiObject win32_operatingsystem).osarchitectu' +
                're -eq "64-bit") { "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" } el' +
                'se { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }; if (Test-Path $RegPath) { $' +
                'RegKey = Get-ChildItem $RegPath | Where-Object { $_.GetValue("DisplayName") -like "*CrowdStrike' +
                ' Windows Sensor*" }; if ($RegKey) { $UninstallString = $RegKey.GetValue("QuietUninstallString")' +
                '; $Arguments = @("/c",$UninstallString); if ($args) { $Arguments += "MAINTENANCE_TOKEN=$args" ' +
                '}; $ArgumentList = $Arguments -join " "; Start-Process -FilePath cmd.exe -ArgumentList $Argumen' +
                'tList -PassThru | Select-Object Id,ProcessName | ForEach-Object { Write-Output "[$($_.Id)]$($' +
                '_.ProcessName) started removal of the Falcon sensor" }}} else { Write-Error "Unable to locate $' +
                'RegPath" }'
        }
    }
    process {
        try {
            $HostInfo = Get-FalconHost -Id $PSBoundParameters.Id | Select-Object cid,device_id,
                platform_name,device_policies
            if ($HostInfo.platform_name -eq 'Mac') {
                throw 'Only Windows and Linux hosts are currently supported in PSFalcon.'
            }
            $IdValue = switch ($HostInfo.device_policies.sensor_update.uninstall_protection) {
                'ENABLED'          { $HostInfo.device_id }
                'MAINTENANCE_MODE' { 'MAINTENANCE' }
            }
            $Token = if ($IdValue) {
                (Get-FalconUninstallToken -DeviceId $IdValue -AuditMessage (
                    "Uninstall-FalconSensor [$((Show-FalconModule).UserAgent)]")).uninstall_token
            }
            $InitParam = @{
                HostId = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline -eq $true) { $true } else { $false }
            }
            $Init = Start-FalconSession @InitParam
            if ($Init.session_id) {
                $CmdParam = @{
                    SessionId = $Init.session_id
                    Command = 'runscript'
                    Argument = '-Raw=```' + $Scripts.($HostInfo.platform_name) + '```'
                }
                if ($Token) { $CmdParam.Argument += " -CommandLine='$Token'" }
                $Request = Invoke-FalconAdminCommand @CmdParam
                if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                    do {
                        Start-Sleep -Seconds 5
                        $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                    } until (
                        $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                    )
                    @($HostInfo | Select-Object cid,device_id).foreach{
                        $Status = if ($Confirm.stdout) { ($Confirm.stdout).Trim() } else { $Confirm.stderr }
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