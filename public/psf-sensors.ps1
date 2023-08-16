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
    [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
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
        $HostList = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,device_policies,tags
        foreach ($Platform in (($HostList.platform_name | Group-Object).Name | Where-Object { @('Linux','Mac',
        'Windows') -contains $_ })) {
          # Start sessions for each 'platform' type
          if ($Platform -eq 'Windows') {
            foreach ($i in ($HostList | Where-Object { $_.platform_name -eq $Platform })) {
              # Check 'tags' for existing values
              [boolean]$TagMatch = $false
              [string[]]$Existing = ($i.tags | Where-Object { $_ -match 'SensorGroupingTags/' }) -replace
                'SensorGroupingTags/',$null
              @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -notcontains $_) { $TagMatch = $true } }
              if ($TagMatch -eq $true) {
                [string]$Script = Get-Content (Join-Path $ScriptPath 'add_sensortag.ps1')
                [string]$TagString = (@($Existing + $Tag) | Select-Object -Unique) -join ','
                [string]$CmdLine = if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                  '-Tag',$TagString,'-Token',($i.device_id | Get-FalconUninstallToken -AuditMessage (
                    'Add-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token -join ' '
                } else {
                  '-Tag',$TagString -join ' '
                }
                $Param = @{
                  Command = 'runscript'
                  Argument = '-Raw=```{0}``` -CommandLine=```{1}```' -f $Script,$CmdLine
                  HostId = $i.device_id
                  QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
                }
                Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
                  # Output device properties and 'tags' value after script
                  [PSCustomObject]@{
                    cid = $i.cid
                    device_id = $_.aid
                    tags = if ($_.stdout) {
                      $Result = ($_.stdout).Trim()
                      if ($Result -match 'Maintenance Token>') { $TagString } else { $Result }
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
          } else {
            [string]$Filename = if ($Platform -eq 'Linux') { 'add_sensortag.sh' } else { 'add_sensortag.zsh' }
            [string]$Script = Get-Content (Join-Path $ScriptPath $Filename)
            $Param = @{
              Command = 'runscript'
              Argument = '-Raw=```{0}``` -CommandLine=```{1}```' -f $Script,($Tag -join ',')
              HostId = ($HostList | Where-Object { $_.platform_name -eq $Platform }).device_id
              QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
            }
            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
              # Output device properties and 'tags' value
              [PSCustomObject]@{
                cid = ($HostList | Where-Object device_id -eq $_.aid).cid
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
    [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [string[]]$Id = @($List | Select-Object -Unique)
      try {
        # Get device info to determine script and begin session
        $HostList = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,tags
        foreach ($Platform in (($HostList.platform_name | Group-Object).Name | Where-Object { @('Linux','Mac',
        'Windows') -contains $_ })) {
          # Start sessions for each 'platform' type
          if ($Platform -eq 'Windows') {
            foreach ($i in ($HostList | Where-Object { $_.platform_name -eq $Platform })) {
              # Use devices API to return tag values
              [PSCustomObject]@{
                cid = $i.cid
                device_id = $i.device_id
                tags = ($i.tags | Where-Object { $_ -match 'SensorGroupingTags/' }) -replace
                  'SensorGroupingTags/',$null -join ','
              }
            }
          } else {
            [string]$Filename = if ($Platform -eq 'Linux') { 'get_sensortag.sh' } else { 'get_sensortag.zsh' }
            [string]$Script = Get-Content (Join-Path $ScriptPath $Filename)
            $Param = @{
              Command = 'runscript'
              Argument = '-Raw=```{0}```' -f $Script
              HostId = ($HostList | Where-Object { $_.platform_name -eq $Platform }).device_id
              QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
            }
            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
              # Output device properties and 'tags' value
              [PSCustomObject]@{
                cid = ($HostList | Where-Object device_id -eq $_.aid).cid
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
    [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
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
        $HostList = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,device_policies,tags
        foreach ($Platform in (($HostList.platform_name | Group-Object).Name | Where-Object { @('Linux','Mac',
        'Windows') -contains $_ })) {
          # Start sessions for each 'platform' type
          if ($Platform -eq 'Windows') {
            foreach ($i in ($HostList | Where-Object { $_.platform_name -eq $Platform })) {
              [boolean]$TagMatch = $false
              [string[]]$Existing = ($i.tags | Where-Object { $_ -match 'SensorGroupingTags/' }) -replace
                'SensorGroupingTags/',$null
              @($Tag).foreach{ if ($TagMatch -eq $false -and $Existing -contains $_) { $TagMatch = $true }}
              if ($TagMatch -eq $true) {
                [string]$Script = Get-Content (Join-Path $ScriptPath 'remove_sensortag.ps1')
                [string]$TagString = (@($Existing + $Tag) | Select-Object -Unique) -join ','
                [string]$CmdLine = if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                  '-Tag',$TagString,'-Token',($i.device_id | Get-FalconUninstallToken -AuditMessage (
                    'Remove-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token -join ' '
                } else {
                  '-Tag',$TagString -join ' '
                }
                $Param = @{
                  Command = 'runscript'
                  Argument = '-Raw=```{0}``` -CommandLine=```{1}```' -f $Script,$CmdLine
                  HostId = $i.device_id
                  QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
                }
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
          } else {
            [string]$Filename = if ($Platform -eq 'Linux') {
              'remove_sensortag.sh'
            } else {
              'remove_sensortag.zsh'
            }
            [string]$Script = Get-Content (Join-Path $ScriptPath $Filename)
            $Param = @{
              Command = 'runscript'
              Argument = '-Raw=```{0}```' -f $Script
              HostId = ($HostList | Where-Object { $_.platform_name -eq $Platform }).device_id
              QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
            }
            Invoke-FalconRtr @Param | Select-Object aid,stdout,stderr,errors | ForEach-Object {
              # Output device properties and 'tags' value
              [PSCustomObject]@{
                cid = ($HostList | Where-Object device_id -eq $_.aid).cid
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
  process {
    try {
      [string[]]$Select = 'cid','device_id','platform_name','device_policies'
      if ($Include) { $Select += $Include }
      $HostList = Get-FalconHost -Id $Id | Select-Object $Select
      if ($HostList.platform_name -notmatch '^(Windows|Linux)$') {
        throw 'Only Windows and Linux hosts are currently supported for uninstallation using PSFalcon.'
      }
      [string]$Filename = if ($Platform -eq 'Linux') {
        'uninstall_sensor.sh'
      } else {
        'uninstall_sensor.ps1'
      }
      [string]$Script = Get-Content (Join-Path (Join-Path (Show-FalconModule).ModulePath 'script') $Filename)
      $Param = @{
        Command = 'runscript'
        Argument = '-Raw=```{0}```' -f $Script
        Timeout = 120
        QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
      }
      [string]$IdValue = switch ($HostList.device_policies.sensor_update.uninstall_protection) {
        'ENABLED' { $HostList.device_id }
        'MAINTENANCE_MODE' { 'MAINTENANCE' }
      }
      if ($IdValue) {
        [string]$Token = ($IdValue | Get-FalconUninstallToken -AuditMessage ("Uninstall-FalconSensor [$(
          (Show-FalconModule).UserAgent)]")).uninstall_token
        if ($Token) { $Param.Argument += (' -CommandLine=```{0}```' -f $Token) }
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