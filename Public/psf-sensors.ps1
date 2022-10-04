function Add-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to add FalconSensorTags to hosts
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.

Provided FalconSensorTag values will be appended to any existing tags.
.PARAMETER Tag
FalconSensorTag value ['FalconSensorTags/<string>']
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconSensorTag
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory,Position=1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [Alias('Tags')]
        [string[]]$Tag,
        [Parameter(Position=2)]
        [boolean]$QueueOffline,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = 'IFS=, read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping ta' +
                'gs are not set//; s/^tags=//; s/.$//"),$1" && IFS=$"\n" uniq=($(printf "%s\n" ${tag[*]} | sort ' +
                ' -u | xargs)) && uniq="$(echo ${uniq[*]} | tr " " ",")" && /opt/CrowdStrike/falconctl -d -f --t' +
                'ags && /opt/CrowdStrike/falconctl -s --tags="$uniq" && /opt/CrowdStrike/falconctl -g --tags | s' +
                'ed "s/^Sensor grouping tags are not set//; s/^tags=//; s/.$//"'
            Mac = 'IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s' +
                '/^No grouping tags set//; s/^Grouping tags: //")) tag+=($1) && uniq=$(echo "${tag[@]}" | tr " "' +
                ' "\n" | sort -u | tr "\n" "," | sed "s/,$//") && /Applications/Falcon.app/Contents/Resources/fa' +
                'lconctl grouping-tags clear &> /dev/null && /Applications/Falcon.app/Contents/Resources/falconc' +
                'tl grouping-tags set "$uniq" &> /dev/null && /Applications/Falcon.app/Contents/Resources/falcon' +
                'ctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"'
            Windows = @{
                Reg = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e04' +
                    '23f-7058-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags" | Wher' +
                    'e-Object { $_ }; $V = if ($T) { (($T -split "REG_SZ")[-1].Trim().Split(",") + $args.Split("' +
                    ',") | Select-Object -Unique) -join "," } else { $args }; [void](reg add $K /v GroupingTags ' +
                    '/d $V /f); "$((((reg query $K) -match "GroupingTags") -split "REG_SZ")[-1].Trim())"'
                Tool = @{
                    Token = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test' +
                        '-Path $E){echo {1} | & "$E" set --grouping-tags "$V"}else{throw "Not found: $E"}'
                    NoToken = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Te' +
                        'st-Path $E){& "$E" set --grouping-tags "$V"}else{throw "Not found: $E"}'
                }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            [string[]]$Id = @($List | Select-Object -Unique)
            [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
            [string]$UserAgent = (Show-FalconModule).UserAgent
            try {
                # Get device info to determine script and begin session
                $Hosts = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,agent_version,
                    device_policies,tags
                foreach ($Platform in ($Hosts.platform_name | Group-Object).Name) {
                    # Start sessions for each 'platform' type
                    $Param = @{ Command = 'runscript' }
                    if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                    if ($Platform -eq 'Windows') {
                        foreach ($i in ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                        $_.agent_version -ge 6.42 })) {
                            # Use 'CsSensorSettings.exe' script for devices 6.42 or newer
                            [boolean]$TagMatch = $false
                            [string[]]$Existing = ($i.tags | Where-Object {
                                $_ -match 'SensorGroupingTags/' }) -replace 'SensorGroupingTags/',$null
                            @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -notcontains $_) {
                                $TagMatch = $true }}
                            if ($TagMatch -eq $true) {
                                [string]$TagString = (@($Existing + $Tag) | Select-Object -Unique) -join ','
                                [string]$Script = if ($i.device_policies.sensor_update.uninstall_protection -eq
                                'ENABLED') {
                                    [string]$Token = ($i.device_id | Get-FalconUninstallToken -AuditMessage (
                                        'Add-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                                    $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString -replace
                                        '\{1\}',$Token
                                } else {
                                    $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString
                                }
                                $Param['Argument'] = '-Raw=```{0}```' -f $Script
                                $Param['HostId'] = $i.device_id
                                Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors |
                                ForEach-Object {
                                    # Output device properties and 'tags' value after script
                                    [PSCustomObject]@{
                                        cid = $i.cid
                                        device_id = $_.aid
                                        tags = if ($_.stdout) {
                                            $Result = ($_.stdout).Trim()
                                            if ($Result -eq 'Maintenance Token>') { $TagString } else { $Result }
                                        } elseif ($_.stderr) {
                                            $_.stderr
                                        } else {
                                            $_.errors
                                        }
                                    }
                                }
                            } else {
                                # Output device properties and 'tags' value when no changes required
                                [PSCustomObject]@{
                                    cid = $i.cid
                                    device_id = $i.device_id
                                    tags = $Existing -join ','
                                }
                            }
                        }
                        if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt
                        6.42 }) {
                            # Run registry modification script for devices older than 6.42
                            $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,
                                ($Tag -join ',')
                            $Param['HostId'] = ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                                $_.agent_version -lt 6.42 }).device_id
                            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                                # Output device properties and 'tags' value
                                [PSCustomObject]@{
                                    cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
                    } else {
                        $Param = @{
                            Command = 'runscript'
                            Argument = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform,($Tag -join ',')
                            HostId = ($Hosts | Where-Object { $_.platform_name -eq $Platform }).device_id
                        }
                        if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                        Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                            # Output device properties and 'tags' value
                            [PSCustomObject]@{
                                cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
}
function Get-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to display FalconSensorTags assigned to hosts
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSensorTag
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position=1)]
        [boolean]$QueueOffline,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = '/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags' +
                '=//; s/.$//"'
            Mac = '/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping' +
                ' tags set//; s/^Grouping tags: //"'
            Windows = '$T = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b' +
                '88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -match "GroupingTags"; if ($T) { "$(($T -' +
                'split "REG_SZ")[-1].Trim())" }'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            [string[]]$Id = @($List | Select-Object -Unique)
            [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
            try {
                # Get device info to determine script and begin session
                $Hosts = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,agent_version,
                    device_policies,tags
                foreach ($Platform in ($Hosts.platform_name | Group-Object).Name) {
                    # Start sessions for each 'platform' type
                    $Param = @{ Command = 'runscript' }
                    if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                    if ($Platform -eq 'Windows') {
                        foreach ($i in ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                        $_.agent_version -ge 6.42 })) {
                            # Use devices API to return tag values for devices 6.42 and newer
                            [PSCustomObject]@{
                                cid = $i.cid
                                device_id = $i.device_id
                                tags = ($i.tags | Where-Object { $_ -match 'SensorGroupingTags/' }) -replace
                                    'SensorGroupingTags/',$null -join ','
                            }
                        }
                        if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt
                        6.42 }) {
                            # Run registry modification script for devices older than 6.42
                            $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,
                                ($Tag -join ',')
                            $Param['HostId'] = ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                                $_.agent_version -lt 6.42 }).device_id
                            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                                # Output device properties and 'tags' value
                                [PSCustomObject]@{
                                    cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
                    } else {
                        $Param = @{
                            Command = 'runscript'
                            Argument = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform,($Tag -join ',')
                            HostId = ($Hosts | Where-Object { $_.platform_name -eq $Platform }).device_id
                        }
                        if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                        Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                            # Output device properties and 'tags' value
                            [PSCustomObject]@{
                                cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
}
function Remove-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to remove FalconSensorTags from hosts
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.

Provided FalconSensorTag values will be removed from existing tags and others will be left unmodified.
.PARAMETER Tag
FalconSensorTag value ['FalconSensorTags/<string>']
.PARAMETER Id
Host identifier
.PARAMETER QueueOffline
Add command request to the offline queue
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSensorTag
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory,Position=1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [Alias('Tags')]
        [string[]]$Tag,
        [Parameter(Position=2)]
        [boolean]$QueueOffline,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Scripts = @{
            Linux = 'IFS=, && read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags ' +
                '| sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"; if [[ ${tag[@]} ]]; then ' +
                '/opt/CrowdStrike/falconctl -d -f --tags && for i in ${del[@]}; do tag=(${tag[@]/$i}); done && I' +
                'FS=$"\n" && val=($(printf "%s\n" ${tag[*]} | xargs)) && val="$(echo ${val[*]} | tr " " ",")" &&' +
                ' /opt/CrowdStrike/falconctl -s --tags="$val"; fi; /opt/CrowdStrike/falconctl -g --tags | sed "s' +
                '/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//"'
            Mac = 'IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s' +
                '/^No grouping tags set//; s/^Grouping tags: //")) del=("${(@s/,/)1}") && for i in ${del[@]}; do' +
                ' tag=("${tag[@]/$i}"); done && tag=$(echo "${tag[@]}" | xargs | tr " " "," | sed "s/,$//") && /' +
                'Applications/Falcon.app/Contents/Resources/falconctl grouping-tags clear &> /dev/null && /Appli' +
                'cations/Falcon.app/Contents/Resources/falconctl grouping-tags set "$tag" &> /dev/null && /Appli' +
                'cations/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags se' +
                't//; s/^Grouping tags: //"'
            Windows = @{
                Reg = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e04' +
                    '23f-7058-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags"; if ($' +
                    'T) {$D = $args.Split(","); $V = ($T -split "REG_SZ")[-1].Trim().Split(",").Where({ $D -notc' +
                    'ontains $_ }) -join ","; if ($V) { [void](reg add $K /v GroupingTags /d $V /f) } else { [vo' +
                    'id](reg delete $K /v GroupingTags /f) }}; $T = (reg query $K) -match "GroupingTags"; if ($T' +
                    ') { ($T -split "REG_SZ")[-1].Trim() }'
                Tool = @{
                    Token = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test' +
                        '-Path $E){if($V){echo {1} | & "$E" set --grouping-tags "$V"}else{echo {1} | & "$E" clea' +
                        'r --grouping-tags}}else{throw "Not found: $E"}'
                    NoToken = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Te' +
                        'st-Path $E){if($V){& "$E" set --grouping-tags "$V"}else{& "$E" clear --grouping-tags}}e' +
                        'lse{throw "Not found: $E"}'
                }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            [string[]]$Id = @($List | Select-Object -Unique)
            [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
            [string]$UserAgent = (Show-FalconModule).UserAgent
            try {
                # Get device info to determine script and begin session
                $Hosts = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,agent_version,
                    device_policies,tags
                foreach ($Platform in ($Hosts.platform_name | Group-Object).Name) {
                    # Start sessions for each 'platform' type
                    $Param = @{ Command = 'runscript' }
                    if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                    if ($Platform -eq 'Windows') {
                        foreach ($i in ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                        $_.agent_version -ge 6.42 })) {
                            # Use 'CsSensorSettings.exe' script for devices 6.42 or newer
                            [boolean]$TagMatch = $false
                            [string[]]$Existing = ($i.tags | Where-Object {
                                $_ -match 'SensorGroupingTags/' }) -replace 'SensorGroupingTags/',$null
                            @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -contains $_) {
                                $TagMatch = $true }}
                            if ($TagMatch -eq $true) {
                                [string]$TagString = ($Existing | Where-Object { $Tag -notcontains $_ }) -join ','
                                [string]$Script = if ($i.device_policies.sensor_update.uninstall_protection -eq
                                'ENABLED') {
                                    [string]$Token = ($i.device_id | Get-FalconUninstallToken -AuditMessage (
                                        'Remove-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                                    $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString -replace
                                        '\{1\}',$Token
                                } else {
                                    $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString
                                }
                                $Param['Argument'] = '-Raw=```{0}```' -f $Script
                                $Param['HostId'] = $i.device_id
                                Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors |
                                ForEach-Object {
                                    # Output device properties and 'tags' value after script
                                    [PSCustomObject]@{
                                        cid = $i.cid
                                        device_id = $_.aid
                                        tags = if ($_.stdout) {
                                            $Result = ($_.stdout).Trim()
                                            if ($Result -eq 'Maintenance Token>') { $TagString } else { $Result }
                                        } elseif ($_.stderr) {
                                            $_.stderr
                                        } else {
                                            $_.errors
                                        }
                                    }
                                }
                            } else {
                                # Output device properties and 'tags' value when no changes required
                                [PSCustomObject]@{
                                    cid = $i.cid
                                    device_id = $i.device_id
                                    tags = $Existing -join ','
                                }
                            }
                        }
                        if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt
                        6.42 }) {
                            # Run registry modification script for devices older than 6.42
                            $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,
                                ($Tag -join ',')
                            $Param['HostId'] = ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                                $_.agent_version -lt 6.42 }).device_id
                            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                                # Output device properties and 'tags' value
                                [PSCustomObject]@{
                                    cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
                    } else {
                        $Param = @{
                            Command = 'runscript'
                            Argument = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform,($Tag -join ',')
                            HostId = ($Hosts | Where-Object { $_.platform_name -eq $Platform }).device_id
                        }
                        if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                        Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                            # Output device properties and 'tags' value
                            [PSCustomObject]@{
                                cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
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
}
function Uninstall-FalconSensor {
<#
.SYNOPSIS
Use Real-time Response to uninstall the Falcon sensor from a host
.DESCRIPTION
Requires 'Hosts: Read', 'Sensor Update Policies: Write', 'Real Time Response: Read', and 'Real Time Response
(Admin): Write'.

This command uses information from the registry and/or relevant Falcon command line utilities of the target host
to uninstall the Falcon sensor. If the sensor is damaged or malfunctioning, Real-time Response may not work
properly and/or the uninstallation may not succeed.
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Include
Include additional properties
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Uninstall-FalconSensor
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position=1)]
        [boolean]$QueueOffline,
        [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Position=2)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip',
            'mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'serial_number','system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('HostId','device_id','host_ids','aid')]
        [string]$Id
    )
    begin {
        $Scripts = @{
            Linux = 'manager=("$(if [[ $(command -v apt) ]]; then echo "apt-get purge falcon-sensor -y"; elif [[' +
                ' $(command -v yum) ]]; then echo "yum remove falcon-sensor -y"; elif [[ $(command -v zypper) ]]' +
                '; then echo "zypper remove -y falcon-sensor"; fi)"); if [[ ${manager} ]]; then echo "Started Re' +
                'moval of the Falcon sensor" && eval "sudo ${manager} &" &>/dev/null; else echo "apt, yum or zyp' +
                'per must be present to begin removal"; fi'
            Mac = $null
            Windows = 'Start-Sleep -Seconds 5; $RegPath = if ((Get-WmiObject win32_operatingsystem).osarchitectu' +
                're -eq "64-bit") { "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" } el' +
                'se { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }; if (Test-Path $RegPath) { $' +
                'RegKey = Get-ChildItem $RegPath | Where-Object { $_.GetValue("DisplayName") -like "*CrowdStrike' +
                ' Windows Sensor*" }; if ($RegKey) { $UninstallString = $RegKey.GetValue("QuietUninstallString")' +
                '; $Arguments = @("/c",$UninstallString); if ($args) { $Arguments += "MAINTENANCE_TOKEN=$args" }' +
                '; $ArgumentList = $Arguments -join " "; Start-Process -FilePath cmd.exe -ArgumentList $Argument' +
                'List -PassThru | Select-Object Id,ProcessName | ForEach-Object { Write-Output "[$($_.Id)] $($_.' +
                'ProcessName) started removal of the Falcon sensor" }}} else { Write-Error "Unable to locate $Re' +
                'gPath" }'
        }
    }
    process {
        try {
            [string[]]$Select = 'cid','device_id','platform_name','device_policies'
            if ($Include) { $Select += $Include }
            $Hosts = Get-FalconHost -Id $Id | Select-Object $Select
            if ($Hosts.platform_name -eq 'Mac') {
                throw 'Only Windows and Linux hosts are currently supported in PSFalcon.'
            }
            $Param = @{
                Command = 'runscript'
                Argument = '-Raw=```{0}```' -f $Scripts.($Hosts.platform_name)
                Timeout = 120
            }
            if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
            [string]$IdValue = switch ($Hosts.device_policies.sensor_update.uninstall_protection) {
                'ENABLED' { $Hosts.device_id }
                'MAINTENANCE_MODE' { 'MAINTENANCE' }
            }
            if ($IdValue) {
                $Token = ($IdValue | Get-FalconUninstallToken -AuditMessage ("Uninstall-FalconSensor [$(
                    (Show-FalconModule).UserAgent)]")).uninstall_token
                if ($Token) { $Param.Argument += " -CommandLine='$Token'" }
            }
            $Request = $Hosts | Invoke-FalconRtr @Param
            if ($Request) {
                [string[]]$Select = 'cid','device_id'
                if ($Include) { $Select += $Include }
                @($Hosts | Select-Object $Select).foreach{
                    $Status = if ($Request.stdout) {
                        ($Request.stdout).Trim()
                    } elseif (!$Request.stdout -and $QueueOffline -eq $true) {
                        'Uninstall request queued'
                    } else {
                        $Request.stderr
                    }
                    Set-Property $_ 'status' $Status
                    $_
                }
            }
        } catch {
            throw $_
        }
    }
}