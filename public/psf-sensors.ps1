function Add-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to add FalconSensorTags to a host
.DESCRIPTION
Provided FalconSensorTag values will be appended to any existing tags. If no new tag values are supplied, a list
of the current tags will be output for the target host. To overwrite existing values, use 'Set-FalconSensorTag'.

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
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin { [System.Collections.Generic.List[string]]$List = @() }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      foreach ($i in @(Get-FalconHost -Id @($List | Select-Object -Unique) | Select-Object cid,device_id,
      platform_name,device_policies,tags)) {
        [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
        [string]$UserAgent = (Show-FalconModule).UserAgent
        [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
        $Output = [PSCustomObject]@{
          cid = $i.cid
          device_id = $i.device_id
          tags = $null
          offline_queued = $false
          session_id = $null
          cloud_request_id = $null
          status = $null
        }
        if (@('Linux','Mac','Windows') -notcontains $i.platform_name) {
          $Output.status = 'UNSUPPORTED_PLATFORM'
        } else {
          try {
            [string[]]$Existing = @($i.tags).Where({ $_ -match 'SensorGroupingTags/' }) -replace
              'SensorGroupingTags/',$null
            [string]$TagString = if ($Existing) {
              # Select tag(s) to append
              [boolean]$Append = $false
              @($Tag).foreach{ if ($Append -eq $false -and $Existing -notcontains $_) { $Append = $true } }
              if ($Append -eq $true) { (@($Existing + $Tag) | Select-Object -Unique) -join ',' }
            } else {
              # Use new tag(s) when none are currently assigned
              ($Tag | Select-Object -Unique) -join ','
            }
            if ($TagString) {
              if ($QueueOffline -eq $true -or ($QueueOffline -eq $false -and
              (Get-FalconHost -Id $i.device_id -State).state -eq 'online')) {
                [string]$CmdLine = if ($i.platform_name -eq 'Windows') {
                  if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                    # Retrieve uninstallation token and add to 'CommandLine' when Windows host is 'online'
                    [string]$Token = (Get-FalconUninstallToken -Id $i.device_id -AuditMessage (
                      'Add-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                    '-Token',$Token,'-Tag',('"{0}"' -f $TagString) -join ' '
                  } else {
                    '-Tag',('"{0}"' -f $TagString) -join ' '
                  }
                } else {
                  $TagString
                }
                # Import RTR script content and run script via RTR
                [string]$Extension = switch ($i.platform_name) {
                  'Linux' { 'sh' }
                  'Mac' { 'zsh' }
                  'Windows' { 'ps1' }
                }
                [string]$ScriptFile = (Join-Path $ScriptPath ('add_sensortag',$Extension -join '.'))
                Write-Log 'Add-FalconSensorTag' "Importing '$ScriptFile'..."
                $Script = Get-Content $ScriptFile -Raw
                $Param = @{
                  Command = 'runscript'
                  Argument = '-Raw=```{0}``` -CommandLine=```{1}```' -f $Script,$CmdLine
                  HostId = $i.device_id
                  QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
                }
                @(Invoke-FalconRtr @Param).foreach{
                  $Output.tags = if ($_.errors) {
                    $_.errors
                  } elseif ($_.stderr) {
                    $_.stderr
                  } elseif ($_.offline_queued -eq $true) {
                    $Output.status = 'PENDING_QUEUE'
                    $Existing -join ','
                  } else {
                    $Output.status = 'TAG_ADDED'
                    $Result = ($_.stdout).Trim()
                    if ($Result -match 'Maintenance Token>') { $TagString } else { $Result }
                  }
                  foreach ($Property in @('offline_queued','session_id','cloud_request_id')) {
                    $Output.$Property = $_.$Property
                  }
                }
              } else {
                # Output existing tags when device is offline
                $Output.tags = $Existing -join ','
                $Output.status = 'HOST_OFFLINE_AND_NOT_QUEUED'
              }
            } else {
              # Output host properties and 'tags' value when no changes required
              $Output.tags = $Existing -join ','
              $Output.status = 'TAG_PRESENT'
            }
          } catch {
            Write-Error $_
          }
        }
        $Output
      }
    }
  }
}
function Get-FalconSensorTag {
<#
.SYNOPSIS
Display FalconSensorTags assigned to hosts
.DESCRIPTION
Returns 'cid', 'device_id', and any FalconSensorTags listed under 'tags' within a 'Get-FalconHost' result.

Requires 'Hosts: Read'.
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSensorTag
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin { [System.Collections.Generic.List[string]]$List = @() }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      @(Get-FalconHost -Id @($List | Select-Object -Unique) | Select-Object cid,device_id,tags).foreach{
        [PSCustomObject]@{
          cid = $_.cid
          device_id = $_.device_id
          tags = @($_.tags).Where({ $_ -match 'SensorGroupingTags/' }) -replace
            'SensorGroupingTags/',$null -join ','
        }
      }
    }
  }
}
function Remove-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to remove FalconSensorTags from a host
.DESCRIPTION
When provided, FalconSensorTag values will be removed from list of existing tags and others will be left
unmodified. If no tags are provided, all existing tags will be removed.

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
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Position=1)]
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
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin { [System.Collections.Generic.List[string]]$List = @() }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
      [string]$UserAgent = (Show-FalconModule).UserAgent
      [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
      foreach ($i in @(Get-FalconHost -Id @($List | Select-Object -Unique) | Select-Object cid,device_id,
      platform_name,device_policies,tags)) {
        $Output = [PSCustomObject]@{
          cid = $i.cid
          device_id = $i.device_id
          tags = $null
          offline_queued = $false
          session_id = $null
          cloud_request_id = $null
          status = $null
        }
        if (@('Linux','Mac','Windows') -notcontains $i.platform_name) {
          $Output.status = 'UNSUPPORTED_PLATFORM'
        } else {
          try {
            [string[]]$Existing = @($i.tags).Where({ $_ -match 'SensorGroupingTags/' }) -replace
              'SensorGroupingTags/',$null
            [string]$TagString = if ($Tag -and $Existing) {
              # Select tag(s) to remove
              [boolean]$Remove = $false
              @($Tag).foreach{ if ($Remove -eq $false -and $Existing -contains $_) { $Remove = $true } }
              if ($Remove -eq $true) {
                (@($Existing).Where({ $Tag -notcontains $_ }) | Select-Object -Unique) -join ','
              }
            }
            if ($Tag -and !$TagString) {
              # Output host properties and 'tags' value when no changes required
              $Output.tags = $Existing -join ','
              $Output.status = 'TAG_NOT_PRESENT'
            } elseif ($QueueOffline -eq $true -or ($QueueOffline -eq $false -and
            (Get-FalconHost -Id $i.device_id -State).state -eq 'online')) {
              [string]$CmdLine = if ($i.platform_name -eq 'Windows') {
                if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
                  # Retrieve uninstallation token and add to 'CommandLine' when host is 'online'
                  [string]$Token = (Get-FalconUninstallToken -Id $i.device_id -AuditMessage (
                    'Remove-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
                  if ($TagString) {
                    '-Token',$Token,'-Tag',('"{0}"' -f $TagString) -join ' '
                  } else {
                    '-Token',$Token -join ' '
                  }
                } elseif ($TagString) {
                  '-Tag',('"{0}"' -f $TagString) -join ' '
                }
              } elseif ($TagString) {
                $TagString
              }
              # Import RTR script content and run script via RTR
              [string]$Extension = switch ($i.platform_name) {
                'Linux' { 'sh' }
                'Mac' { 'zsh' }
                'Windows' { 'ps1' }
              }
              [string]$ScriptFile = (Join-Path $ScriptPath ('remove_sensortag',$Extension -join '.'))
              Write-Log 'Remove-FalconSensorTag' "Importing '$ScriptFile'..."
              $Script = Get-Content $ScriptFile -Raw
              $Param = @{
                Command = 'runscript'
                Argument = '-Raw=```{0}```' -f $Script
                HostId = $i.device_id
                QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
              }
              if ($CmdLine) { $Param.Argument += (' -CommandLine=```{0}```' -f $CmdLine) }
              @(Invoke-FalconRtr @Param).foreach{
                $Output.tags = if ($_.errors) {
                  $_.errors
                } elseif ($_.stderr) {
                  $_.stderr
                } elseif ($_.offline_queued -eq $true) {
                  $Output.status = 'PENDING_QUEUE'
                  $Existing -join ','
                } else {
                  $Output.status = if ($TagString) { 'TAG_REMOVED' } else { 'TAG_CLEARED' }
                  $Result = ($_.stdout).Trim()
                  if ($Result -match 'Maintenance Token>') { $TagString } else { $Result }
                }
                foreach ($Property in @('offline_queued','session_id','cloud_request_id')) {
                  $Output.$Property = $_.$Property
                }
              }
            } else {
              # Output existing tags when device is offline
              $Output.tags = $Existing -join ','
              $Output.status = 'HOST_OFFLINE_AND_NOT_QUEUED'
            }
          } catch {
            Write-Error $_
          }
        }
        $Output
      }
    }
  }
}
function Set-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to set FalconSensorTags on a host
.DESCRIPTION
Provided FalconSensorTag values will overwrite any existing tags.

Requires 'Hosts: Read', 'Sensor update policies: Write' and 'Real time response (admin): Write'.
.PARAMETER Tag
FalconSensorTag value ['FalconSensorTags/<string>']
.PARAMETER QueueOffline
Add command request to the offline queue
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconSensorTag
#>
  [CmdletBinding(SupportsShouldProcess)]
  [OutputType([PSCustomObject])]
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
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id
  )
  process {
    [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
    [string]$UserAgent = (Show-FalconModule).UserAgent
    [string[]]$Tag = $Tag -replace 'SensorGroupingTags/',$null
    $i = Get-FalconHost -Id $Id | Select-Object cid,device_id,platform_name,device_policies,tags
    $Output = [PSCustomObject]@{
      cid = $i.cid
      device_id = $i.device_id
      tags = (@($i.tags).Where({ $_ -match 'SensorGroupingTags/' }) -replace 'SensorGroupingTags/',
        $null) -join ','
      offline_queued = $false
      session_id = $null
      cloud_request_id = $null
      status = $null
    }
    if (@('Linux','Mac','Windows') -notcontains $i.platform_name) {
      $Output.status = 'UNSUPPORTED_PLATFORM'
    } else {
      try {
        # Import RTR script content
        [string]$Extension = switch ($i.platform_name) {
          'Linux' { 'sh' }
          'Mac' { 'zsh' }
          'Windows' { 'ps1' }
        }
        [string]$ScriptFile = (Join-Path $ScriptPath ('add_sensortag',$Extension -join '.'))
        Write-Log 'Set-FalconSensorTag' "Importing '$ScriptFile'..."
        $Script = Get-Content $ScriptFile -Raw
        [string]$TagString = ($Tag | Select-Object -Unique) -join ','
        if ($QueueOffline -eq $true -or ($QueueOffline -eq $false -and
        (Get-FalconHost -Id $i.device_id -State).state -eq 'online')) {
          [string]$CmdLine = if ($i.platform_name -eq 'Windows') {
            if ($i.device_policies.sensor_update.uninstall_protection -eq 'ENABLED') {
              # Retrieve uninstallation token and add to 'CommandLine' when host is 'online'
              [string]$Token = (Get-FalconUninstallToken -Id $i.device_id -AuditMessage (
                'Set-FalconSensorTag',"[$UserAgent]" -join ' ')).uninstall_token
              '-Token',$Token,'-Tag',('"{0}"' -f $TagString) -join ' '
            } else {
              '-Tag',('"{0}"' -f $TagString) -join ' '
            }
          } else {
            $TagString
          }
          # Run script via RTR
          $Param = @{
            Command = 'runscript'
            Argument = '-Raw=```{0}``` -CommandLine=```{1}```' -f $Script,$CmdLine
            HostId = $i.device_id
            QueueOffline = if ($QueueOffline) { $QueueOffline } else { $false }
          }
          @(Invoke-FalconRtr @Param).foreach{
            if ($_.offline_queued -eq $true) {
              $Output.status = 'PENDING_QUEUE'
            } else {
              $Output.tags = if ($_.errors) {
                $_.errors
              } elseif ($_.stderr) {
                $_.stderr
              } else {
                $Output.status = 'TAG_SET'
                $Result = ($_.stdout).Trim()
                if ($Result -match 'Maintenance Token>') { $TagString } else { $Result }
              }
            }
            foreach ($Property in @('offline_queued','session_id','cloud_request_id')) {
              $Output.$Property = $_.$Property
            }
          }
        } else {
          # Output status when device is offline
          $Output.status = 'HOST_OFFLINE_AND_NOT_QUEUED'
        }
      } catch {
        Write-Error $_
      }
      $Output
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
      [string]$Filename = if ($Platform -eq 'Linux') { 'uninstall_sensor.sh' } else { 'uninstall_sensor.ps1' }
      [string]$Script = Get-Content (Join-Path (Join-Path (Show-FalconModule).ModulePath 'script') $Filename) -Raw
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