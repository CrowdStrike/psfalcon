function Add-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to add FalconSensorTags to hosts
.DESCRIPTION
Provided FalconSensorTag values will be appended to any existing tags.

Requires 'Hosts: Read', 'Sensor update policies: Write' and 'Real time response (admin): Write'.
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
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('Ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin {
    $Scripts = @{
      Linux = 'IFS=, read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are' +
        ' not set//; s/^tags=//; s/.$//"),$1" && IFS=$"\n" uniq=($(printf "%s\n" ${tag[*]} | sort -u | xargs)) &' +
        '& uniq="$(echo ${uniq[*]} | tr " " ",")" && /opt/CrowdStrike/falconctl -d -f --tags && /opt/CrowdStrike' +
        '/falconctl -s --tags="$uniq" && /opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are' +
        ' not set//; s/^tags=//; s/.$//"'
      Mac = 'IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No g' +
        'rouping tags set//; s/^Grouping tags: //")) tag+=($1) && uniq=$(echo "${tag[@]}" | tr " " "\n" | sort -' +
        'u | tr "\n" "," | sed "s/,$//") && /Applications/Falcon.app/Contents/Resources/falconctl grouping-tags ' +
        'clear &> /dev/null && /Applications/Falcon.app/Contents/Resources/falconctl grouping-tags set "$uniq" &' +
        '> /dev/null && /Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No gro' +
        'uping tags set//; s/^Grouping tags: //"'
      Windows = @{
        Reg = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058' +
          '-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags" | Where-Object { $_ }; $' +
          'V = if ($T) { (($T -split "REG_SZ")[-1].Trim().Split(",") + $args.Split(",") | Select-Object -Unique)' +
          ' -join "," } else { $args }; [void](reg add $K /v GroupingTags /d $V /f); "$((((reg query $K) -match ' +
          '"GroupingTags") -split "REG_SZ")[-1].Trim())"'
        Tool = @{
          Token = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test-Path $E){' +
            'echo {1} | & "$E" set --grouping-tags "$V"}else{throw "Not found: $E"}'
          NoToken = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test-Path $E' +
            '){& "$E" set --grouping-tags "$V"}else{throw "Not found: $E"}'
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
              @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -notcontains $_) { $TagMatch = $true }}
              if ($TagMatch -eq $true) {
                [string]$TagString = (@($Existing + $Tag) | Select-Object -Unique) -join ','
                [string]$Script = if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                  [string]$Token = ($i.device_id | Get-FalconUninstallToken -AuditMessage (
                    'Add-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                  $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString -replace '\{1\}',$Token
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
            if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt 6.42 }) {
              # Run registry modification script for devices older than 6.42
              $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,($Tag -join ',')
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
                tags = if ($_.stdout) { ($_.stdout).Trim() } elseif ($_.stderr) { $_.stderr } else { $_.errors }
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
Requires 'Hosts: Read' and 'Real time response (admin): Write'.
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
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('Ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin {
    $Scripts = @{
      Linux = '/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s' +
        '/.$//"'
      Mac = '/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags ' +
        'set//; s/^Grouping tags: //"'
      Windows = '$T = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{' +
        '16e0423f-7058-48c9-a204-725362b67639}\Default") -match "GroupingTags"; if ($T) { "$(($T -split "REG_SZ"' +
        ')[-1].Trim())" }'
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
            if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt 6.42 }) {
              # Run registry modification script for devices older than 6.42
              $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,($Tag -join ',')
              $Param['HostId'] = ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                $_.agent_version -lt 6.42 }).device_id
              Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                # Output device properties and 'tags' value
                [PSCustomObject]@{
                  cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
                  device_id = $_.aid
                  tags = if ($_.stdout) { ($_.stdout).Trim() } elseif ($_.stderr) { $_.stderr } else { $_.errors }
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
                tags = if ($_.stdout) { ($_.stdout).Trim() } elseif ($_.stderr) { $_.stderr } else { $_.errors }
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
Provided FalconSensorTag values will be removed from existing tags and others will be left unmodified.

Requires 'Hosts: Read', 'Sensor update policies: Write' and 'Real time response (admin): Write'.
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
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('Ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin {
    $Scripts = @{
      Linux = 'IFS=, && read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed ' +
        '"s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"; if [[ ${tag[@]} ]]; then /opt/CrowdStri' +
        'ke/falconctl -d -f --tags && for i in ${del[@]}; do tag=(${tag[@]/$i}); done && IFS=$"\n" && val=($(pri' +
        'ntf "%s\n" ${tag[*]} | xargs)) && val="$(echo ${val[*]} | tr " " ",")" && /opt/CrowdStrike/falconctl -s' +
        ' --tags="$val"; fi; /opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//;' +
        ' s/^tags=//; s/.$//"'
      Mac = 'IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No g' +
        'rouping tags set//; s/^Grouping tags: //")) del=("${(@s/,/)1}") && for i in ${del[@]}; do tag=("${tag[@' +
        ']/$i}"); done && tag=$(echo "${tag[@]}" | xargs | tr " " "," | sed "s/,$//") && /Applications/Falcon.ap' +
        'p/Contents/Resources/falconctl grouping-tags clear &> /dev/null && /Applications/Falcon.app/Contents/Re' +
        'sources/falconctl grouping-tags set "$tag" &> /dev/null && /Applications/Falcon.app/Contents/Resources/' +
        'falconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"'
      Windows = @{
        Reg = '$K = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058' +
          '-48c9-a204-725362b67639}\Default"; $T = (reg query $K) -match "GroupingTags"; if ($T) {$D = $args.Spl' +
          'it(","); $V = ($T -split "REG_SZ")[-1].Trim().Split(",").Where({ $D -notcontains $_ }) -join ","; if ' +
          '($V) { [void](reg add $K /v GroupingTags /d $V /f) } else { [void](reg delete $K /v GroupingTags /f) ' +
          '}}; $T = (reg query $K) -match "GroupingTags"; if ($T) { ($T -split "REG_SZ")[-1].Trim() }'
        Tool = @{
          Token = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test-Path $E){' +
            'if($V){echo {1} | & "$E" set --grouping-tags "$V"}else{echo {1} | & "$E" clear --grouping-tags}}els' +
            'e{throw "Not found: $E"}'
          NoToken = '$V="{0}";$E=Join-Path $env:ProgramFiles "CrowdStrike\CsSensorSettings.exe";if (Test-Path $E' +
            '){if($V){& "$E" set --grouping-tags "$V"}else{& "$E" clear --grouping-tags}}else{throw "Not found: ' +
            '$E"}'
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
              @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -contains $_) { $TagMatch = $true }}
              if ($TagMatch -eq $true) {
                [string]$TagString = ($Existing | Where-Object { $Tag -notcontains $_ }) -join ','
                [string]$Script = if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                  [string]$Token = ($i.device_id | Get-FalconUninstallToken -AuditMessage (
                    'Remove-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                  $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString -replace '\{1\}',$Token
                } else {
                  $Scripts.$Platform.Tool.Token -replace '\{0\}',$TagString
                }
                $Param['Argument'] = '-Raw=```{0}```' -f $Script
                $Param['HostId'] = $i.device_id
                Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
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
            if ($Hosts | Where-Object { $_.platform_name -eq $Platform -and $_.agent_version -lt 6.42 }) {
              # Run registry modification script for devices older than 6.42
              $Param['Argument'] = '-Raw=```{0}``` -CommandLine="{1}"' -f $Scripts.$Platform.Reg,($Tag -join ',')
              $Param['HostId'] = ($Hosts | Where-Object { $_.platform_name -eq $Platform -and
                $_.agent_version -lt 6.42 }).device_id
              Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                # Output device properties and 'tags' value
                [PSCustomObject]@{
                  cid = ($Hosts | Where-Object device_id -eq $_.aid).cid
                  device_id = $_.aid
                  tags = if ($_.stdout) { ($_.stdout).Trim() } elseif ($_.stderr) { $_.stderr } else { $_.errors }
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
                tags = if ($_.stdout) { ($_.stdout).Trim() } elseif ($_.stderr) { $_.stderr } else { $_.errors }
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
This command uses information from the registry and/or relevant Falcon command line utilities of the target host
to uninstall the Falcon sensor. If the sensor is damaged or malfunctioning, Real-time Response may not work
properly and/or the uninstallation may not succeed.

Requires 'Hosts: Read', 'Sensor update policies: Write', 'Real time response: Read', and 'Real Time Response
(Admin): Write'.
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
    [Parameter(Position=2)]
    [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip',
      'mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
      'serial_number','system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('HostId','device_id','host_ids','aid')]
    [string]$Id
  )
  begin {
    $Scripts = @{
      Linux = 'manager=("$(if [[ $(command -v apt) ]]; then echo "apt-get purge falcon-sensor -y"; elif [[ $(com' +
        'mand -v yum) ]]; then echo "yum remove falcon-sensor -y"; elif [[ $(command -v zypper) ]]; then echo "z' +
        'ypper remove -y falcon-sensor"; fi)"); if [[ ${manager} ]]; then echo "Started removal of the Falcon se' +
        'nsor" && eval "sudo ${manager} &" &>/dev/null; else echo "apt, yum or zypper must be present to begin r' +
        'emoval"; fi'
      Mac = $null
      Windows = '$t=$args;$sp=Join-Path $env:ProgramFiles (Join-Path "CrowdStrike" "CSFalconService.exe");if(!(T' +
        'est-Path $sp)){throw "Unable to locate $sp"};$bv=if((Get-CimInstance win32_operatingsystem).OSArchitect' +
        'ure -match "64"){"WOW6432Node\"};$rp="HKLM:\SOFTWARE\$($bv)Microsoft\Windows\CurrentVersion\Uninstall";' +
        'if(!(Test-Path $rp)){throw "Unable to locate $rp"};@(gci $rp).Where({$_.GetValue("DisplayName") -match ' +
        '"CrowdStrike(.+)?Sensor"}).foreach{if((gi $sp).VersionInfo.FileVersion -eq $_.GetValue("DisplayVersion"' +
        ')){$us=if($_.GetValue("QuietUninstallString")){$_.GetValue("QuietUninstallString")}else{$_.GetValue("Un' +
        'installString")};if(!$us){throw "Failed to find UninstallString value for $($_.GetValue("DisplayName"))' +
        '"};$al=@("/c",$us);if($t){$al+="MAINTENANCE_TOKEN=$t"};"Starting removal of the Falcon sensor";[void](s' +
        'tart -FilePath cmd.exe -ArgumentList ($al -join " ") -PassThru)}}'
    }
  }
  process {
    try {
      [string[]]$Select = 'cid','device_id','platform_name','device_policies'
      if ($Include) { $Select += $Include }
      $HostList = Get-FalconHost -Id $Id | Select-Object $Select
      if ($HostList.platform_name -eq 'Mac') {
        throw 'Only Windows and Linux hosts are currently supported in PSFalcon.'
      }
      $Param = @{
        Command = 'runscript'
        Argument = '-Raw=```{0}```' -f $Scripts.($HostList.platform_name)
        Timeout = 120
      }
      if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
      [string]$IdValue = switch ($HostList.device_policies.sensor_update.uninstall_protection) {
        'ENABLED' { $HostList.device_id }
        'MAINTENANCE_MODE' { 'MAINTENANCE' }
      }
      if ($IdValue) {
        $Token = ($IdValue | Get-FalconUninstallToken -AuditMessage ("Uninstall-FalconSensor [$(
          (Show-FalconModule).UserAgent)]")).uninstall_token
        if ($Token) { $Param.Argument += " -CommandLine='$Token'" }
      }
      $Request = $HostList | Invoke-FalconRtr @Param
      if ($Request) {
        [string[]]$Select = 'cid','device_id'
        if ($Include) { $Select += $Include }
        @($HostList | Select-Object $Select).foreach{
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