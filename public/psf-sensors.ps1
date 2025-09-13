function Invoke-TagScript {
  param(
    [Parameter(Mandatory,Position=1)]
    [object]$Object,
    [Parameter(Mandatory,Position=2)]
    [ValidateSet('Add','Remove','Set',IgnoreCase=$false)]
    [string]$Action,
    [Parameter(Mandatory,Position=3)]
    [boolean]$QueueOffline,
    [Parameter(Position=4)]
    [string[]]$String
  )
  process {
    # Gather existing tags, check for uninstall protection and define initial output
    [string]$Protection = $Object.device_policies.sensor_update.uninstall_protection
    $Output = [PSCustomObject]@{
      cid = $Object.cid
      device_id = $Object.device_id
      tags = @(@($Object.tags).Where({$_ -match 'SensorGroupingTags/'}) -replace 'SensorGroupingTags/',$null)
      offline_queued = $false
      session_id = $null
      cloud_request_id = $null
      status = if (@('Linux','Mac','Windows') -notcontains $Object.platform_name) {
        # Abort when 'platform_name' is unexpected
        'UNSUPPORTED_PLATFORM'
      } elseif ($Object.platform_name -ne 'Windows' -and $Protection -eq 'ENABLED') {
        # Abort when uninstall protection is enabled and platform_name is not 'Windows'
        'NO_TOKEN_SUPPORT_FOR_OS'
      }
    }
    # Abort when no tags are present to 'Remove'
    if ($Action -eq 'Remove' -and !$Output.tags) { $Output.status = 'NO_TAG_SET' }
    if (!$Output.status) {
      [string[]]$TagInput = $String -replace 'SensorGroupingTags/',$null
      [string]$TagString = if (($Action -eq 'Add' -and !$Output.tags) -or $Action -eq 'Set') {
        # Select all provided tags when using 'Set', or 'Add' and no tags exist
        ($TagInput | Select-Object -Unique) -join ','
      } elseif ($Action -eq 'Add' -and $TagInput) {
        [boolean[]]$Append = @($TagInput).foreach{ if ($Output.tags -notcontains $_) { $true } else { $false }}
        if ($Append -eq $true) {
          # Append to existing tag(s)
          (@($Output.tags + $TagInput) | Select-Object -Unique) -join ','
        } else {
          # Abort when tag(s) to 'Add' are already present
          $Output.status = 'TAG_PRESENT'
        }
      } elseif ($Action -eq 'Remove' -and $TagInput) {
        [boolean[]]$Remove = @($TagInput).foreach{ if ($Output.tags -contains $_) { $true } else { $false }}
        if ($Remove -eq $true) {
          # Remove from existing tag(s)
          (@($Output.tags).Where({$TagInput -notcontains $_})) -join ','
        } else {
          # Abort when tag(s) to 'Remove' are not present
          $Output.status = 'TAG_NOT_PRESENT'
        }
      }
      if (!$Output.status) {
        # Verify that device is currently online
        [string]$State = (Get-FalconHost -Id $Object.device_id -State).state
        if ($QueueOffline -eq $true -or ($QueueOffline -eq $false -and $State -eq 'online')) {
          # Add quotes around tag value string for Windows script use
          if ($TagString) { $TagString = ('"{0}"' -f $TagString) }
          [string]$CmdLine = if ($Protection -eq 'ENABLED') {
            # Retrieve uninstallation token and add to 'CommandLine' when host is 'online'
            [string]$Token = (Get-FalconUninstallToken -Id $Object.device_id -AuditMessage (($Action,
              'FalconSensorTag' -join '-'),"[$((Show-FalconModule).UserAgent)]" -join ' ')).uninstall_token
            if ($TagString) { $TagString,$Token -join ' ' } else { $Token }
          } elseif ($TagString) {
            $TagString
          }
          # Import script content and run script using Real-time Response
          [string]$ScriptPath = Join-Path (Show-FalconModule).ModulePath 'script'
          [string]$ScriptName = if ($Action -eq 'Remove' -and !$TagString) {
            'remove_sensortag'
          } else {
            'add_sensortag'
          }
          [string]$Extension = switch ($Object.platform_name) {
            'Linux' { 'sh' }
            'Mac' { 'zsh' }
            'Windows' { 'ps1' }
          }
          [string]$ScriptFile = (Join-Path $ScriptPath ($ScriptName,$Extension -join '.'))
          if (!(Test-Path $ScriptFile)) { throw "Failed to locate '$ScriptFile'." }
          Write-Log ($Action,'FalconSensorTag' -join '-') "Importing '$ScriptFile'..."
          $ScriptContent = Get-Content $ScriptFile -Raw
          $Param = @{
            Command = 'runscript'
            Argument = '-Raw=```{0}```' -f $ScriptContent
            HostId = $Object.device_id
            QueueOffline = $QueueOffline
          }
          if ($CmdLine) { $Param.Argument += (' -CommandLine=```{0}```' -f $CmdLine) }
          @(Invoke-FalconRtr @Param).foreach{
            # Capture offline queue status, 'errors' or 'stderr' in 'status'
            $Output.status = if ($_.offline_queued -eq $true) {
              'PENDING_QUEUE'
            } elseif ($_.errors) {
              $_.errors
            } elseif ($_.stderr) {
              $_.stderr
            } elseif ($_.stdout) {
              # Compare 'stdout' with $TagInput and update 'status'
              $Result = ($_.stdout).Trim()
              $Output.tags = if ($Result -match 'Maintenance Token>') {
                if ($TagString) { ($TagString).Trim('"') }
              } else {
                $Result
              }
              [string[]]$FinalValue = $Output.tags -split ','
              if ($Action -eq 'Remove') {
                [boolean[]]$Removed = @($Tag).foreach{ if ($FinalValue -contains $_) { $false } else { $true }}
                if ($Removed -ne $false) { 'TAG_REMOVED' } else { 'TAG_NOT_REMOVED' }
              } else {
                [boolean[]]$Set = @($Tag).foreach{ if ($FinalValue -contains $_) { $true } else { $false }}
                if ($Set -ne $false) {
                  if ($Action -eq 'Add') { 'TAG_ADDED' } else { 'TAG_SET' }
                } else {
                  if ($Action -eq 'Add') { 'TAG_NOT_ADDED' } else { 'TAG_NOT_SET' }
                }
              }
            }
            # Append Real-time response properties to initial output
            foreach ($i in @('offline_queued','session_id','cloud_request_id')) { $Output.$i = $_.$i }
          }
        } else {
          # Abort if host is offline and 'QueueOffline' is false
          'HOST_OFFLINE_AND_NOT_QUEUED'
        }
      }
    }
    $Output.tags = $Output.tags -join ','
    $Output
  }
}
function Add-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to add SensorGroupingTags to a host
.DESCRIPTION
Provided SensorGroupingTag values will be appended to any existing tags. If no new tag values are supplied, a list
of the current tags will be output for the target host. To overwrite existing values, use 'Set-FalconSensorTag'.

Requires 'Hosts: Read', 'Sensor update policies: Write', 'Real time response: Read', and
'Real time response (admin): Write'.
.PARAMETER Tag
SensorGroupingTag value ['SensorGroupingTags/<string>']
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
      foreach ($i in @(Get-FalconHost -Id $List | Select-Object cid,device_id,platform_name,device_policies,
      tags)) {
        Invoke-TagScript $i 'Add' $QueueOffline $Tag
      }
    }
  }
}
function Get-FalconSensorTag {
<#
.SYNOPSIS
Display SensorGroupingTags assigned to hosts
.DESCRIPTION
Returns 'cid', 'device_id', and any SensorGroupingTags listed under 'tags' within a 'Get-FalconHost' result.

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
      @(Get-FalconHost -Id $List | Select-Object cid,device_id,tags).foreach{
        [PSCustomObject]@{
          cid = $_.cid
          device_id = $_.device_id
          tags = @($_.tags).Where({$_ -match 'SensorGroupingTags/'}) -replace 'SensorGroupingTags/',
            $null -join ','
        }
      }
    }
  }
}
function Remove-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to remove SensorGroupingTags from a host
.DESCRIPTION
When provided, SensorGroupingTag values will be removed from list of existing tags and others will be left
unmodified. If no tags are provided, all existing tags will be removed.

Requires 'Hosts: Read', 'Sensor update policies: Write', 'Real time response: Read', and
'Real time response (admin): Write'.
.PARAMETER Tag
SensorGroupingTag value ['SensorGroupingTags/<string>']
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
      foreach ($i in @(Get-FalconHost -Id $List | Select-Object cid,device_id,platform_name,device_policies,
      tags)) {
        Invoke-TagScript $i 'Remove' $QueueOffline $Tag
      }
    }
  }
}
function Set-FalconSensorTag {
<#
.SYNOPSIS
Use Real-time Response to set SensorGroupingTags on a host
.DESCRIPTION
Provided SensorGroupingTag values will overwrite any existing tags. To append to existing values, use
'Add-FalconSensorTag'.

Requires 'Hosts: Read', 'Sensor update policies: Write', 'Real time response: Read', and
'Real time response (admin): Write'.
.PARAMETER Tag
SensorGroupingTag value ['FalconSensorTags/<string>']
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
  begin { [System.Collections.Generic.List[string]]$List = @() }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      foreach ($i in @(Get-FalconHost -Id $List | Select-Object cid,device_id,platform_name,device_policies,
      tags)) {
        Invoke-TagScript $i 'Set' $QueueOffline $Tag
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
      [string]$Filename = if ($HostList.platform_name -eq 'Linux') {
        'uninstall_sensor.sh'
      } else {
        'uninstall_sensor.ps1'
      }
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