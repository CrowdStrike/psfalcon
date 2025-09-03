function Export-FalconConfig {
<#
.SYNOPSIS
Create an archive containing Falcon configuration files
.DESCRIPTION
Uses various PSFalcon commands to gather and export groups, policies and exclusions as a collection of Json files
within a zip archive. The exported files can be used with 'Import-FalconConfig' to restore configurations to your
existing CID or create them in another CID.
.PARAMETER Select
Selected items to export from your current CID, or leave unspecified to export all available items
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Export-FalconConfig
#>
  [CmdletBinding(DefaultParameterSetName='ExportItem',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='ExportItem',Position=1)]
    [ValidateSet('ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup',
      'FirewallLocation','FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion',
      'PreventionPolicy','ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [Alias('Items')]
    [string[]]$Select,
    [Parameter(ParameterSetName='ExportItem')]
    [switch]$Force
  )
  begin {
    function Add-AssignedItem ([string]$String,[PSCustomObject[]]$Obj) {
      function Assert-IdList ([string]$String) {
        # Add key to 'AddList'
        if (!$AddList.ContainsKey($String)) { $AddList[$String] = [System.Collections.Generic.List[string]]@() }
      }
      if ($String -match '(Exclusion|Ioc|Policy)$' -and $Select -notcontains 'HostGroup') {
        # Add identifiers for assigned 'HostGroup'
        Assert-IdList HostGroup
        if ($Obj.groups) {
          if ($Obj.groups.id) {
            @($Obj.groups.id).foreach{ $AddList.HostGroup.Add($_) }
          } else {
            @($Obj.groups).foreach{ $AddList.HostGroup.Add($_) }
          }
        } elseif ($Obj.host_groups -and $Obj.host_groups.id) {
          @($Obj.host_groups.id).foreach{ $AddList.HostGroup.Add($_) }
        } elseif ($String -eq 'Ioc' -and $Obj.host_groups) {
          @($Obj.host_groups).foreach{ $AddList.HostGroup.Add($_) }
        }
      }
      if ($String -eq 'FirewallGroup' -and $Obj.rule_ids) {
        # Add identifiers for assigned 'FirewallRule'
        Assert-IdList FirewallRule
        @($Obj.rule_ids).foreach{ $AddList.FirewallRule.Add($_) }
      }
      if ($String -eq 'FirewallPolicy' -and $Select -notcontains 'FirewallGroup') {
        # Add identifiers for assigned 'FirewallGroup'
        Assert-IdList FirewallGroup
        if ($Obj.settings -and $Obj.settings.rule_group_ids) {
          @($Obj.settings.rule_group_ids).foreach{ $AddList.FirewallGroup.Add($_) }
        }
      }
      if ($String -eq 'FirewallRule' -and $Select -notcontains 'FirewallLocation') {
        # Add 'FirewallLocation' identifiers when assigned to 'FirewallRule'
        Assert-IdList FirewallLocation
        @(@($Obj.fields).Where({$_.name -eq 'network_location'}).values | Select-Object -Unique).Where({
        $FwLocation -notcontains $_}).foreach{
          $AddList.FirewallLocation.Add($_)
        }
      }
      if ($String -eq 'FileVantagePolicy' -and $Select -notcontains 'FileVantageRuleGroup') {
        # Add identifiers for assigned 'rule_group_ids' to list of 'FileVantageRuleGroup'
        Assert-IdList FileVantageRuleGroup
        if ($Obj.rule_groups -and $Obj.rule_groups.id) {
          @($Obj.rule_groups.id).foreach{ $AddList.FileVantageRuleGroup.Add($_) }
        }
      }
      if ($String -eq 'PreventionPolicy' -and $Select -notcontains 'IoaGroup') {
        # Add identifiers for assigned 'ioa_rule_groups' to list of 'IoaGroup'
        Assert-IdList IoaGroup
        if ($Obj.ioa_rule_groups -and $Obj.ioa_rule_groups.id) {
          @($Obj.ioa_rule_groups.id).foreach{ $AddList.IoaGroup.Add($_) }
        }
      }
    }
    function Get-ItemContent ([string]$String,[string[]]$Id) {
      # Request content for provided 'Item'
      $Message = if ($Id) {
        '[Export-FalconConfig] Exporting assigned "{0}"...' -f $String
      } else {
        '[Export-FalconConfig] Exporting "{0}"...' -f $String
      }
      Write-Host $Message
      $Param = @{ Detailed = $true; All = $true }
      [string]$ConfigFile = Join-Path $Location ($String,'json' -join '.')
      [PSCustomObject[]]$Config = if ($String -match '^FileVantage(Policy|RuleGroup)$') {
        [string]$Filter = if ($String -eq 'FileVantagePolicy') {
          # Filter to user-created FileVantagePolicy
          '$_.created_by -ne "cs-cloud-provisioning" -and $_.name -notmatch "^Default Policy \((Linux|Mac|' +
            'Windows)\)$"'
        } else {
          # Filter to user-created FileVantageRuleGroup
          '$_.created_by -ne "internal"'
        }
        if ($String -eq 'FileVantagePolicy' ) { $Param['Include'] = 'exclusions' }
        @((Get-Command "Get-Falcon$String").Parameters.Type.Attributes.ValidValues).foreach{
          # Retrieve FileVantagePolicy/RuleGroup for each 'Type'
          & "Get-Falcon$String" @Param -Type $_ 2>$null |
            Where-Object -FilterScript ([scriptblock]::Create($Filter))
        }
      } elseif ($String -match '(?<!Content)Policy$') {
        if ($String -eq 'FirewallPolicy') { $Param['Include'] = 'settings' }
        @('Windows','Mac','Linux').foreach{
          # Create policy exports in 'platform_name' order to retain precedence
          & "Get-Falcon$String" -Filter "platform_name:'$_'" @Param 2>$null
        }
      } else {
        & "Get-Falcon$String" @Param 2>$null
      }
      if ($Config -and $Id) {
        # Filter export to specific objects by 'Property'
        $Property = if ($String -eq 'FirewallRule') { 'family' } else { 'id' }
        [PSCustomObject[]]$Config = @($Config).Where({$Id -contains $_.$Property})
      }
      if ($Config) {
        # Verify that assigned items are included in export
        Add-AssignedItem $String $Config
        if ($String -eq 'FileVantageRuleGroup') {
          foreach ($i in $Config) {
            # Update 'assigned_rules' with rule content inside FileVantage rule groups
            [string[]]$RuleId = @($i.assigned_rules.id).Where({![string]::IsNullOrWhiteSpace($_)})
            if ($RuleId) {
              Write-Host ('[Export-FalconConfig] Exporting rules for {0} group "{1}"...' -f $i.type,$i.name)
              $i.assigned_rules = @(Get-FalconFileVantageRule -RuleGroupId $i.id -Id $RuleId)
            }
          }
        }
        try {
          # Export results to json file and output created file name
          ConvertTo-Json @($Config) -Depth 32 | Out-File $ConfigFile -Append
          $ConfigFile
        } catch {
          throw "Unable to write to '$((Get-Location).Path)'. Try 'Export-FalconConfig' in a new location."
        }
      }
    }
    # Get current location and set output archive path
    $Location = (Get-Location).Path
    $ExportFile = Join-Path $Location "FalconConfig_$((Get-Date -Format FileDateTime) -replace '\d{4}$',$null).zip"
  }
  process {
    if (!$Select) {
      # Use items in 'ValidateSet' when not provided
      [string[]]$Select = @((Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({$_.Name -eq
        'ExportItem'}).Parameters.Where({$_.Name -eq 'Select'}).Attributes.ValidValues).foreach{ $_ }
    }
    $OutPath = Test-OutFile $ExportFile
    if ($OutPath.Category -eq 'WriteError' -and !$Force) {
      Write-Error @OutPath
    } else {
      $AddList = @{}
      [System.Collections.Generic.List[string]]$JsonFiles = @()
      foreach ($String in $Select) {
        # Create Json export and capture file name
        @(Get-ItemContent $String).foreach{ $JsonFiles.Add($_) }
      }
      if ($JsonFiles -and $AddList.GetEnumerator().Where({$_.Value})) {
        do {
          foreach ($p in @($AddList.GetEnumerator().Where({$_.Value}) | Select-Object -First 1)) {
            # Retrieve assigned groups when not added to 'Select'
            $JsonFiles.Add((Get-ItemContent $p.Key $p.Value))
            $AddList.Remove($p.Key)
          }
        } while (@($AddList.GetEnumerator()).Where({$_.Value}))
      }
      if ($JsonFiles -and $PSCmdlet.ShouldProcess($ExportFile,'Compress-Archive')) {
        # Archive Json exports with content and remove them when complete
        $Param = @{
          Path = @(Get-ChildItem).Where({$JsonFiles -contains $_.FullName -and $_.Length -gt 0}).FullName
          DestinationPath = $ExportFile
          Force = $Force
        }
        Compress-Archive @Param
        @($JsonFiles).foreach{
          if (Test-Path $_) {
            Write-Log 'Export-FalconConfig' "Removing '$_'"
            Remove-Item $_ -Force
          }
        }
      }
      # Display created archive
      if (Test-Path $ExportFile) { Get-ChildItem $ExportFile | Select-Object FullName,Length,LastWriteTime }
    }
  }
}
function Import-FalconConfig {
<#
.SYNOPSIS
Import items from a 'FalconConfig' archive into your Falcon environment
.DESCRIPTION
Creates groups, policies, exclusions, rules and scripts within a 'FalconConfig' archive within your authenticated
Falcon environment.

Anything that already exists will be ignored and no existing items will be modified unless the relevant parameters
are included.

If using 'Select', any dependencies are added based on your input and whether or not the 'AssignExisting' switch
is included.

'Sensor Download: Read' permission is required for CID comparison in Flight Control environments, and 'Read' and
'Write' permissions are required for all items being imported.
.PARAMETER Path
FalconConfig archive path
.PARAMETER Select
Import selected files from archive
.PARAMETER AssignExisting
Assign existing host groups with identical names to imported items
.PARAMETER ModifyDefault
Modify default policies to match import. Use 'All' for all possible values (or all values in 'Select')
.PARAMETER ModifyExisting
Modify existing items to match import. Use 'All' for all possible values (or all values in 'Select')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Import-FalconConfig
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('\.zip$')]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist or is not a file."
      }
    })]
    [string]$Path,
    [ValidateSet('ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup',
      'FirewallLocation','FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion',
      'PreventionPolicy','ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [string[]]$Select,
    [Alias('Force')]
    [switch]$AssignExisting,
    [ValidateSet('All','ContentPolicy','DeviceControlPolicy','PreventionPolicy','ResponsePolicy',
      'SensorUpdatePolicy')]
    [string[]]$ModifyDefault,
    [ValidateSet('All','ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup',
      'FirewallGroup','FirewallLocation','FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc',
      'MlExclusion','PreventionPolicy','ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [string[]]$ModifyExisting
  )
  begin {
    function Add-Result {
      # Create result object for CSV output
      param(
        [ValidateSet('Created','Failed','Ignored','Modified')]
        [string]$Action,
        [PSCustomObject]$Item,
        [string]$Type,
        [string]$Property,
        [string]$Old,
        [string]$New,
        [string]$Comment,
        [string]$Log
      )
      $Result = [PSCustomObject]@{
        time = Get-Date -Format o
        api_client_id = if ($Action -eq 'Ignored') { $null } else { $Script:Falcon.ClientId }
        type = $Type
        id = if ($Type -eq 'FileVantageRule') {
          'rule_group_id',$Item.rule_group_id -join ':'
        } elseif ($Item.instance_id) {
          $Item.instance_id
        } elseif ($Item.family) {
          $Item.family
        } else {
          $Item.id
        }
        name = if ($Type -eq 'FileVantageRule') {
          'precedence',$Item.precedence -join ':'
        } else {
          Select-ObjectName $Item $Type
        }
        platform = if ($Item.platform) {
          $Item.platform -join ','
        } elseif ($Item.platforms) {
          $Item.platforms -join ','
        } elseif ($Item.platform_name) {
          $Item.platform_name
        } elseif ($Type -eq 'IoaRule' -and $Item.rulegroup_id) {
          # Use 'os' from IoaGroup reference to populate IoaRule 'platform'
          @($Config.IoaGroup.Ref).Where({$_.new.Equals($Item.rulegroup_id)}).os
        } elseif ($Type -match '^FileVantageRule(Group)?$') {
          $Item.type
        } elseif ($Type -eq 'FileVantageExclusion' -and $Item.policy_id) {
          # Use 'os' from FileVantagePolicy reference to populate FileVantageExclusion 'platform'
          @($Config.FileVantagePolicy.Ref).Where({$_.new.Equals($Item.policy_id)}).os
        } elseif ($Type -eq 'FirewallRule' -and $Item.rule_group.id) {
          # Use 'os' from FirewallGroup reference to populate FirewallRule 'platform'
          @($Config.FirewallGroup.Ref).Where({$_.new.Equals($Item.rule_group.id)}).os
        } else {
          $null
        }
        action = $Action
        property = $Property
        old_value = $Old
        new_value = $New
        comment = if ($Comment) {
          $Comment
        } elseif ($Item.family -and $Item.rule_group.id) {
          'rule_group_id',$Item.rule_group.id -join ':'
        } elseif ($Item.policy_id -and $Item.id) {
          'policy_id',$Item.policy_id -join ':'
        }
      }
      # Create Result list to contain results when not present and output result
      if (!$Config.ContainsKey($Type)) { $Config[$Type] = @{} }
      if (!$Config.$Type.ContainsKey('Result')) {
        $Config.$Type['Result'] = [System.Collections.Generic.List[PSCustomObject]]@()
      }
      # Update 'old' and 'new' value to ensure 'False' is present
      if ($Result.old_value -eq 'True' -and !$Result.new_value) {
        Set-Property $Result new_value 'False'
      } elseif ($Result.new_value -eq 'True' -and !$Result.old_value) {
        Set-Property $Result old_value 'False'
      }
      $Config.$Type.Result.Add($Result)
      if ($Action -match '^(Created|Failed|Modified)$') {
        # Notify when items are created or modified or when failures occur
        [System.Collections.Generic.List[string]]$Notify = @('[Import-FalconConfig]',$Action)
        if ($Log) { $Notify.Add($Log) }
        if ($Type -eq 'DeviceControlPolicy' -and $Property -match '\.exceptions') {
          if ($Comment) {
            # Name for modified DeviceControlPolicy exceptions
            $Notify.Add(('"{0}" in' -f $Comment))
          } elseif ($New) {
            # Name for new DeviceControlPolicy exceptions
            $Notify.Add(('"{0}" in' -f $New))
          }
        } elseif ($Property) {
          $Notify.Add(('"{0}" for' -f $Property))
        }
        if ($Result.platform -and $Result.platform -notmatch ',' -and $Type -notmatch
        'ContentPolicy|(FileVantage|Firewall)Rule') {
          $Notify.Add($Result.platform)
        }
        $Notify.Add($Type)
        if ($Type -eq 'FileVantageRule') {
          $Notify.Add(('{0} in "{1}".' -f $Result.name,@($Config.FileVantageRuleGroup.Ref).Where({
            $_.new.Equals($Item.rule_group_id)}).name))
        } elseif ($Type -eq 'FileVantageExclusion') {
          $Notify.Add(('"{0}" in "{1}".' -f $Result.name,@($Config.FileVantagePolicy.Ref).Where({
            $_.new.Equals($Item.policy_id)}).name))
        } else {
          $Notify.Add(('"{0}".' -f $Result.name))
        }
        Write-Host ($Notify -join ' ')
      }
      # Export result to CSV
      try { $Result | Export-Csv $OutputFile -NoTypeInformation -Append } catch { Write-Error $_ }
    }
    function Clear-ConfigList {
      param(
        [string]$Item,
        [string]$Key
      )
      # Remove sub-key from Config
      if ($Config.$Item.ContainsKey($Key)) {
        [void]$Config.$Item.Remove($Key)
        Write-Log 'Clear-ConfigList' ('Removed "{0}" from "{1}"' -f $Key,$Item)
      }
    }
    function Compare-Setting {
      param(
        [PSCustomObject]$New,
        [PSCustomObject]$Old,
        [string]$Item,
        [string]$Property,
        [switch]$Result
      )
      if ($Item -eq 'ContentPolicy') {
        [string[]]$Select = foreach ($i in $New.settings.ring_assignment_settings) {
          [PSCustomObject]$Ref = $Old.settings.ring_assignment_settings | Where-Object { $_.id -eq $i.id }
          if ($i -and $Ref) {
            @($i.PSObject.Properties.Name + $Ref.PSObject.Properties.Name | Select-Object -Unique).foreach{
              if ($_ -eq 'override') {
                if (($i.$_.value -and !$Ref.$_.value) -or (!$i.$_.value -and $Ref.$_.value) -or
                (($i.$_.value -and $Ref.$_.value) -and ($i.$_.value -ne $Ref.$_.value))) {
                  if ($Result) {
                    # Capture result
                    Add-Result Modified $New $Item ($i.id,$_,'value' -join '.') $Ref.$_.value $i.$_.value
                  } else {
                    # Output 'override' when 'value' does not match
                    $_
                  }
                }
              } elseif (($i.$_ -and !$Ref.$_) -or (!$i.$_ -and $Ref.$_) -or (($i.$_ -and $Ref.$_) -and
              ($i.$_ -ne $Ref.$_))) {
                if ($Result) {
                  # Capture result
                  Add-Result Modified $New $Item ($i.id,$_ -join '.') $Ref.$_ $i.$_
                } else {
                  # Output property name when values do not match
                  $_
                }
              }
            }
          } else {
            # Notify when 'ring_assignment_settings' are not present on $New or $Old
            Write-Log 'Compare-Setting' (($Item,$New.name -join ':'),
              'Unable to compare "ring_assignment_settings"' -join "`n ")
          }
        }
        if ($Select) {
          # Output settings for modification
          Write-Log 'Compare-Setting' (($Item,$New.name -join ':'),($Select -join ',') -join "`n ")
          $New.settings
        }
      } elseif ($Item -eq 'DeviceControlPolicy') {
        if ($Result) {
          # Capture DeviceControlPolicy results
          foreach ($t in @('bluetooth_settings','usb_settings')) {
            if ($New.$t) {
              foreach ($p in @($New.$t.PSObject.Properties)) {
                if ($p.Name -match 'custom(_end_user)?_notifications') {
                  # Compare 'custom_notifications' properties
                  $NewNote = $p.Value | ConvertTo-Json -Compress
                  $OldNote = $Old.$t.($p.Name) | ConvertTo-Json -Compress
                  if ($NewNote -ne $OldNote) {
                    # Capture modified property result
                    Add-Result Modified $New $Item ($t,$p.Name -join '.') $OldNote $NewNote
                  }
                } elseif ($p.Name -ne 'classes' -and $p.Value -ne $Old.$t.($p.Name)) {
                  # Capture modified property result
                  Add-Result Modified $New $Item ($t,$p.Name -join '.') $Old.$t.($p.Name) $p.Value
                }
              }
              # Compare 'classes' with existing DeviceControlPolicy classes
              foreach ($c in $New.$t.classes) {
                $RefC = @($Old.$t.classes).Where({$_.class -eq $c.class}) |
                Select-Object id,action,class,minor_classes,
                @{
                  l='exceptions'
                  e={
                    @($Config.$Item.ExCid).Where({$_.policy_id -eq $Old.id -and $_.type -eq $t}) |
                    Select-Object id,class,vendor_id,vendor_name,product_id,product_name,serial_number,combined_id,
                    action,match_method,description,minor_classes
                  }
                }
                if ($c.minor_classes) {
                  # Compare 'minor_classes' under 'bluetooth_settings'
                  foreach ($m in $c.minor_classes) {
                    $RefM = @($RefC.minor_classes).Where({$_.minor_class -eq $m.minor_class})
                    if ($RefM -and $m.action -ne $RefM.action) {
                      # Capture modified 'action' under 'minor_classes'
                      Add-Result Modified $New $Item ($c.class,$m.minor_class,
                        'action' -join '.') $RefM.action $m.action
                    }
                  }
                }
                if ($c.action -ne $RefC.action) {
                  # Capture 'action' result for class
                  Add-Result Modified $New $Item ($c.class,'action' -join '.') $RefC.action $c.action
                }
                foreach ($e in $c.exceptions) {
                  # Compare exclusions to find new or modified results
                  $Filter = Write-SelectFilter $e DeviceControlException
                  if ($Filter) {
                    # Compare new exceptions against existing exceptions in target DeviceControlPolicy
                    $RefE = $RefC.exceptions | Where-Object -FilterScript $Filter
                    $eObj = [PSCustomObject]$e | Select-Object @($e.PSObject.Properties.Name).Where({
                      $_ -notmatch '^(id|policy_id|type)$'})
                    $eName = ($eObj.match_method,((@(Select-ObjectName $eObj DeviceControlException).foreach{
                      $eObj.$_ }) -join '_') -join ':')
                    if (!$RefE) {
                      # Capture new exception results
                      Add-Result Created $New $Item ($c.class,'exceptions' -join '.') -New $eName
                    } elseif ($RefE -and $e.action -ne $RefE.action) {
                      # Capture modified 'action' result for exception
                      Add-Result Modified $New $Item ($c.class,'exceptions','action' -join '.') $RefE.action (
                        $eObj.action) -Comment $eName
                    }
                  }
                }
              }
            }
          }
        } else {
          # Select DeviceControlPolicy exceptions and settings to modify
          $Output = @{ exception = @{}; setting = @{ bluetooth_settings = @{}; usb_settings = @{} } }
          foreach ($t in @('bluetooth_settings','usb_settings')) {
            if ($New.$t) {
              foreach ($p in @($New.$t.PSObject.Properties)) {
                if ($p.Name -match 'custom(_end_user)?_notifications') {
                  # Compare 'custom_notifications' properties
                  $NewNote = $p.Value | ConvertTo-Json -Compress
                  $OldNote = $Old.$t.($p.Name) | ConvertTo-Json -Compress
                  if ($NewNote -and $NewNote -ne $OldNote) { $Output.setting.$t[$p.Name] = $p.Value }
                } elseif ($p.Name -ne 'classes' -and $p.Value -ne $Old.$t.($p.Name)) {
                  # Capture modified property content
                  $Output.setting.$t[$p.Name] = $p.Value
                }
              }
              # Compare 'classes' with existing DeviceControlPolicy classes
              foreach ($c in $New.$t.classes) {
                $RefC = @($Old.$t.classes).Where({$_.class -eq $c.class}) |
                Select-Object id,action,class,minor_classes,
                @{
                  l='exceptions'
                  e={
                    @($Config.$Item.ExCid).Where({$_.policy_id -eq $Old.id -and $_.type -eq $t}) |
                    Select-Object id,class,vendor_id,vendor_name,product_id,product_name,serial_number,combined_id,
                    action,match_method,description,minor_classes
                  }
                }
                if ($c.minor_classes) {
                  # Compare 'minor_classes' under 'bluetooth_settings'
                  [System.Collections.Generic.List[PSCustomObject]]$McList = @()
                  foreach ($m in $c.minor_classes) {
                    $RefM = @($RefC.minor_classes).Where({$_.minor_class -eq $m.minor_class})
                    if ($RefM -and $m.action -ne $RefM.action) {
                      # Add 'minor_class' with existing 'id' and new 'action' value
                      Update-Id $m $RefM $Item
                      $McList.Add(([PSCustomObject]$m | Select-Object action,minor_class))
                    }
                  }
                  # Add 'minor_classes' that require changes
                  if ($McList) { $c.minor_classes = $McList }
                }
                $ExList = [System.Collections.Generic.List[PSCustomObject]]@()
                foreach ($e in @($Config.$Item.ExImp).Where({$_.policy_id -eq $New.id -and $_.type -eq $t -and
                $_.class -eq $c.class})) {
                  $Filter = Write-SelectFilter $e DeviceControlException
                  if ($Filter) {
                    # Compare new exceptions against existing exceptions in target DeviceControlPolicy
                    $RefE = $RefC.exceptions | Where-Object -FilterScript $Filter
                    $eObj = [PSCustomObject]$e | Select-Object @($e.PSObject.Properties.Name).Where({
                      $_ -notmatch '^(id|policy_id|type)$'})
                    $eName = ($eObj.match_method,((@(Select-ObjectName $eObj DeviceControlException).foreach{
                      $eObj.$_ }) -join '_') -join ':')
                    if (!$RefE) {
                      # Capture missing exceptions for modification
                      $ExList.Add($eObj)
                    } elseif ($RefE -and $RefE.action -ne $e.action) {
                      # Use existing exception 'id' for modification of 'action'
                      Set-Property $eObj id $RefE.id
                      $ExList.Add($eObj)
                    }
                  }
                }
                if ($ExList -or $c.action -ne $RefC.action) {
                  # Add 'bluetooth_classes' or 'usb_classes' for modification
                  $tClass = $t -replace '_settings','_classes'
                  if (!$Output.exception.$tClass) { $Output.exception[$tClass] = @{} }
                  if ($c.action -ne $RefC.action) {
                    # Select properties for 'bluetooth_classes' or 'usb_classes'
                    if (!$Output.exception.$tClass.classes) {
                      # Add 'classes' list
                      $Output.exception.$tClass['classes'] = [System.Collections.Generic.List[PSCustomObject]]@()
                    }
                    # Add 'class' to list when 'action' is different
                    $Output.exception.$tClass.classes.Add(([PSCustomObject]$c |
                      Select-Object @($c.PSObject.Properties.Name).Where({$_ -notmatch '^(id|exceptions)$'})))
                  }
                  if ($ExList) {
                    if (!$Output.exception.$tClass.upsert_exceptions) {
                      # Add 'upsert_exceptions' list
                      $Output.exception.$tClass['upsert_exceptions'] =
                        [System.Collections.Generic.List[PSCustomObject]]@()
                    }
                    # Add new or modified exception to list
                    @($ExList).foreach{ $Output.exception.$tClass.upsert_exceptions.Add($_) }
                  }
                }
              }
            }
          }
          if ($Output.setting.bluetooth_settings.Count -or $Output.setting.usb_settings.Count -or
          $Output.exception.Count) {
            # Output DeviceControlPolicy settings and exceptions
            @('bluetooth_settings','usb_settings').foreach{
              # Remove empty 'bluetooth_settings' or 'usb_settings'
              if (!$Output.setting.$_.Count) { $Output.setting.Remove($_) }
            }
            # Add policy identifier for modification
            @('exception','setting').foreach{ if ($Output.$_.Count) { $Output.$_['id'] = $Old.id } }
            $Output
          } else {
            # Capture ignored result
            Add-Result Ignored $New $Item -Comment Identical
          }
        }
      } elseif ($Item -eq 'FirewallPolicy') {
        @($New.settings.PSObject.Properties).Where({$_.Name -notmatch '^((platform|policy)_id|tracking)$' -and
        $_.Value -ne $Old.settings.($_.Name)}).foreach{
          if ($Result) {
            # Capture result
            Add-Result Modified $New $Item $_.Name ($Old.settings.($_.Name) -join ',') ($_.Value -join ',')
          } else {
            # Output 'true' to flag entire 'settings' object for modification
            $true
          }
        }
      } elseif ($Item -eq 'SensorUpdatePolicy') {
        [string[]]$Select = if ($Old) {
          foreach ($i in @($New.settings.PSObject.Properties)) {
            if ($i.Name -match '^(scheduler|variants)$') {
              if ($Result) {
                # Capture 'scheduler' and 'variants' result as json string
                $OldJson = $Old.settings.($i.Name) | ConvertTo-Json -Compress
                $NewJson = $i.Value | ConvertTo-Json -Compress
                if ($NewJson -ne $OldJson) { Add-Result Modified $New $Item $i.Name $OldJson $NewJson }
              } else {
                # Check for modified 'scheduler' or 'variants' sub-property
                [boolean[]]$SubProp = @($i.Value).foreach{
                  @($_.PSObject.Properties).foreach{
                    if ($_.Value -ne $Old.settings.($i.Name).($_.Name)) { $true } else { $false }
                  }
                }
                # Output property name when modified sub-properties are present
                if ($SubProp -eq $true) { $i.Name }
              }
            } else {
              if ($i.Value -ne $Old.settings.($i.Name)) {
                if ($Result) {
                  # Capture result
                  Add-Result Modified $New $Item $i.Name $Old.settings.($i.Name) $i.Value
                } else {
                  # Output modified property name
                  $i.Name
                }
              }
            }
          }
        }
        # Output settings to be modified by property name
        if ($Select) { $New.settings | Select-Object $Select }
      } elseif ($Item -match 'Policy$') {
        # Compare modified policy settings with 'id' and 'value' sub-properties
        $NewArr = $New.settings
        $OldArr = $Old.settings
        if ($OldArr -or $Result) {
          foreach ($i in $NewArr) {
            if ($i.value.PSObject.Properties.Name -eq 'enabled') {
              if ($OldArr.Where({$_.id -eq $i.id}).value.enabled -ne $i.value.enabled) {
                if ($Result) {
                  # Capture modified result for boolean settings
                  Add-Result Modified $New $Item $i.id $OldArr.Where({$_.id -eq
                    $i.id}).value.enabled $i.value.enabled
                } else {
                  # Output setting to be modified
                  Write-Log 'Compare-Setting' (($Item,$New.id -join ': '),([PSCustomObject]@{id=$i.id;old=(
                    $OldArr.Where({$_.id -eq $i.id}).value | ConvertTo-Json -Compress);new=($i.value |
                    ConvertTo-Json -Compress)} | Format-List | Out-String).Trim() -join "`n")
                  $i | Select-Object id,value
                }
              }
            } else {
              foreach ($n in $i.value.PSObject.Properties.Name) {
                if ($OldArr.Where({$_.id -eq $i.id}).value.$n -ne $i.value.$n) {
                  if ($Result) {
                    # Capture modified result for sub-settings
                    Add-Result Modified $New $Item ($i.id,$n -join ':') @($OldArr).Where({$_.id -eq
                      $i.id}).value.$n $Item.value.$n
                  } else {
                    # Output setting to be modified
                    Write-Log 'Compare-Setting' (($Item,$New.id -join ': '),([PSCustomObject]@{id=$i.id;old=(
                      $OldArr.Where({$_.id -eq $i.id}).value | ConvertTo-Json -Compress);new=($i.value |
                      ConvertTo-Json -Compress)} | Format-List | Out-String).Trim() -join "`n")
                    $i | Select-Object id,value
                  }
                }
              }
            }
          }
        } else {
          # Output new settings
          if ($NewArr.id) { $NewArr | Select-Object id,value } else { $NewArr }
        }
      } elseif ($Result) {
        # Compare other modified item properties
        if ($Property -eq 'field_values') {
          foreach ($Name in $New.$Property.name) {
            # Track 'field_values' for IoaRule for each modified value
            $OldFv = @($Old.$Property).Where({$_.name -eq $Name}).values | ConvertTo-Json -Compress
            $NewFv = @($New.$Property).Where({$_.name -eq $Name}).values | ConvertTo-Json -Compress
            if ($NewFv -ne $OldFv) { Add-Result Modified $New $Item $Name $OldFv $NewFv }
          }
        } elseif ($Property) {
          if ($New.$Property -ne $Old.$Property) {
            # Capture specific modified property
            Add-Result Modified $New $Item $Property $Old.$Property $New.$Property
          }
        } else {
          @($New.PSObject.Properties.Name).Where({$_ -notmatch '^(id|comment)$'}).foreach{
            # Capture modified properties, excluding 'id' and 'comment'
            if ($New.$_ -ne $Old.$_) { Add-Result Modified $New $Item $_ $Old.$_ $New.$_ }
          }
        }
      }
    }
    function Compress-Object {
      param(
        [PSCustomObject[]]$Obj,
        [string]$Item
      )
      $Select = switch ($Item) {
        'ContentPolicy' {
          'cid','id','name','platform_name','description','enabled',@{l='groups';e={$_.groups |
          Select-Object id,name}},'settings'
        }
        'DeviceControlPolicy' {
          'cid','id','name','platform_name','description','enabled',
          @{
            l='groups'
            e={
              if ($_.groups -and $_.groups.id -and $_.groups.name) {
                $_.groups | Select-Object id,name
              } else {
                $_.groups
              }
            }
          },
          @{
            l='bluetooth_settings'
            e={
              $_.bluetooth_settings | Select-Object enforcement_mode,end_user_notification,
              @{
                # Ensure 'blocked_notification' and 'restricted_notification' are present
                l='custom_end_user_notifications'
                e={
                  $_.custom_end_user_notifications | Select-Object @{l='blocked_notification';e={
                    $_.blocked_notification | Select-Object use_custom,custom_message}},@{
                    l='restricted_notification';e={$_.restricted_notification | Select-Object use_custom,
                    custom_message}}
                }
              },
              @{
                # Ensure expected 'classes' properties are present
                l='classes'
                e={
                  $_.classes | Select-Object id,action,
                    @{l='class';e={if ($_.class) { $_.class } else { $_.id }}},
                    @{l='minor_classes';e={$_.minor_classes | Select-Object id,minor_class,action}}
                }
              }
            }
          },
          @{
            # Convert 'settings' to 'usb_settings'
            l='usb_settings'
            e={
              $SubProp = if ($_.settings) { 'settings' } else { 'usb_settings' }
              $_.$SubProp | Select-Object end_user_notification,enforcement_mode,
              enhanced_file_metadata,whitelist_mode,
              @{
                # Ensure 'blocked_notification' and 'restricted_notification' are present
                l='custom_notifications'
                e={
                  $_.custom_notifications | Select-Object @{l='blocked_notification';e={$_.blocked_notification |
                    Select-Object use_custom,custom_message}},@{l='restricted_notification';e={
                    $_.restricted_notification | Select-Object use_custom,custom_message}}
                }
              },
              @{
                # Ensure expected 'classes' properties are present
                l='classes'
                e={
                  $_.classes | Select-Object id,action,@{l='class';e={if ($_.class) { $_.class } else { $_.id }}}
                }
              }
            }
          }
        }
        'FileVantagePolicy' {
          'cid','id','name','platform','enabled','rule_groups','host_groups'
        }
        'FileVantageRuleGroup' {
          'id','name','type','assigned_rules','policy_assignments'
        }
        'FirewallGroup' {
          @{l='cid';e={$_.customer_id}},'id','name','platform','enabled','deleted','description','rule_ids',
          'policy_ids','rules'
        }
        'FirewallLocation' {
          'cid','id','name','enabled','description','rule_count','host_addresses','default_gateways',
          'dhcp_servers','dns_servers','connection_types','https_reachable_hosts','icmp_request_targets',
          'dns_resolution_targets','metadata'
        }
        'FirewallPolicy' {
          'cid','id','name','platform_name','description','enabled','channel_version','rule_set_id',
          @{l='groups';e={$_.groups | Select-Object id,name}},
          @{
            l='settings'
            e={
              # Exclude timestamps from FirewallPolicy 'settings'
              $_.settings | Select-Object @($_.settings.PSObject.Properties.Name).Where({
                @('created_by','created_on','modified_by','modified_on') -notcontains $_
              })
            }
          }
        }
        'FirewallRule' {
          'id','family','name','enabled','deleted','direction','action','address_family','protocol',
          'fqdn_enabled','fqdn','version','description','fields','icmp','local_address','local_port','monitor',
          'remote_address','remote_port',@{l='rule_group';e={$_.rule_group | Select-Object id,name,platform}}
        }
        'HostGroup' {
          'id','group_type','name','assignment_rule','description'
        }
        'IoaExclusion' {
          'id','name','pattern_id','pattern_name','cl_regex','ifn_regex','applied_globally',@{l='groups';
          e={$_.groups | Select-Object id,name}}
        }
        'IoaGroup' {
          @{l='cid';e={$_.customer_id}},'id','name','platform','enabled','deleted','version','description',
          'rule_ids','rules'
        }
        'Ioc' {
          'id','type','value','platforms','severity','deleted','expiration','action','mobile_action','tags',
          'applied_globally','host_groups'
        }
        'MlExclusion' {
          'id','value','applied_globally','excluded_from',@{l='groups';e={$_.groups | Select-Object id,name}},
          @{l='is_descendant_process';e={
            # Force 'is_descendant_process' to false when not present
            if ([string]::IsNullOrEmpty($_.is_descendant_process)) { $false } else { $_.is_descendant_process }
          }}
        }
        'PreventionPolicy' {
          'cid','id','name','platform_name','description','enabled',@{l='ioa_rule_groups';
          e={$_.ioa_rule_groups | Select-Object id,name}},@{l='groups';e={$_.groups | Select-Object id,name}},
          @{l='settings';e={$_.prevention_settings.settings | Select-Object id,value}}
        }
        'ResponsePolicy' {
          'cid','id','name','platform_name','description','enabled',@{l='groups';e={$_.groups |
          Select-Object id,name}},@{l='settings';e={$_.settings.settings | Select-Object id,value}}
        }
        'Script' {
          'id','name','platform','content','sha256','permission_type','write_access','share_with_workflow',
          'workflow_is_disruptive'
        }
        'SensorUpdatePolicy' {
          'cid','id','name','platform_name','description','enabled',@{l='groups';e={$_.groups |
          Select-Object id,name}},'settings'
        }
        'SvExclusion' {
          'id','value','applied_globally',@{l='groups';e={$_.groups | Select-Object id,name}},
          @{
            l='is_descendant_process'
            e={
              # Force 'is_descendant_process' to false when not present
              if ([string]::IsNullOrEmpty($_.is_descendant_process)) { $false } else { $_.is_descendant_process }
            }
          }
        }
      }
      # Return selected properties, or return unexpected items unmodified
      if ($Select) { $Obj | Select-Object $Select } else { $Obj }
    }
    function Confirm-InputValue {
      foreach ($i in @('Default','Existing')) {
        if ($UserDict -and $UserDict.ContainsKey("Modify$i")) {
          # Update 'All' to valid values for 'ModifyDefault' and 'ModifyExisting', or values in 'Select'
          $Output = [System.Collections.Generic.List[string]]@()
          if ($UserDict."Modify$i" -contains 'All' -and $UserDict."Valid$i") {
            if ($UserDict.ContainsKey('Select')) {
              @($UserDict."Valid$i").Where({$UserDict.Select -contains $_}).foreach{ $Output.Add($_) }
            } else {
              @($UserDict."Valid$i").foreach{ $Output.Add($_) }
            }
          } elseif ($UserDict.ContainsKey('Select')) {
            @($UserDict."Modify$i").Where({$UserDict.Select -contains $_}).foreach{ $Output.Add($_) }
          } else {
            @($UserDict."Modify$i").foreach{ $Output.Add($_) }
          }
          $UserDict["Modify$i"] = $Output
        }
      }
      if ($UserDict -and $UserDict.ContainsKey('Select')) {
        # Add dependent values to Select for evaluation (not creation/modification)
        if ($UserDict.AssignExisting) {
          # When AssignExisting is present
          if ($UserDict.Select -match '(Exclusion|Ioc|Policy)$' -and $UserDict.Select -notcontains 'HostGroup') {
            # HostGroup when importing Exclusion, Ioc, or Policy
            $UserDict.Select += 'HostGroup'
          }
          if ($UserDict.Select -contains 'PreventionPolicy' -and $UserDict.Select -notcontains 'IoaGroup') {
            # IoaGroup with PreventionPolicy
            $UserDict.Select += 'IoaGroup'
          }
          if ($UserDict.Select -contains 'FileVantagePolicy' -and $UserDict.Select -notcontains
          'FileVantageRuleGroup') {
            # FileVantageRuleGroup with FileVantagePolicy
            $UserDict.Select += 'FileVantageRuleGroup'
          }
          if ($UserDict.Select -contains 'FirewallPolicy' -and $UserDict.Select -notcontains 'FirewallGroup') {
            # FirewallGroup with FirewallPolicy
            $UserDict.Select += 'FirewallGroup'
          }
        }
        if ($UserDict.Select -contains 'FileVantageRuleGroup' -and $UserDict.Select -notcontains
        'FileVantageRule') {
          # FileVantageRule with FileVantageRuleGroup
          $UserDict.Select += 'FileVantageRule'
        }
        if ($UserDict.Select -contains 'FirewallGroup' -and $UserDict.Select -notcontains 'FirewallRule') {
          # FirewallRule with FirewallGroup
          $UserDict.Select += 'FirewallRule'
        }
      }
      # Log and return updated input values
      $UserDict.GetEnumerator().Where({$_.Key -match '^(Modify(Default|Existing)|Select)$'}).foreach{
        Write-Log 'Confirm-InputValue' ("$($_.Key):"," $($_.Value -join ',')" -join "`n")
      }
    }
    function Edit-Item {
      param(
        [PSCustomObject]$Obj,
        [string]$Item,
        [string]$Comment
      )
      if ($Obj) {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        $Ref = $Config.$Item.Cid | Where-Object -FilterScript (Write-SelectFilter $Obj $Item)
        if ($Ref -and $Item -eq 'FileVantageRuleGroup') {
          foreach ($Ar in $Obj.assigned_rules) {
            # Get matching rule from target CID
            $RefAr = $Ref.assigned_rules | Where-Object -FilterScript (Write-SelectFilter $Ar FileVantageRule)
            if ($RefAr) {
              # Evaluate and each FileVantageRule
              [string[]]$PropList = @($Ar.PSObject.Properties.Name).Where({$_ -notmatch
              '^(id|rule_group_id|type)$'}).foreach{
                if (!$RefAr.$_ -or $RefAr.$_ -ne $Ar.$_) {
                  if ($_ -notmatch '^content_(files|registry_values)$' -or ($_ -match
                  '^content_(files|registry_values)$' -and ![string]::IsNullOrWhiteSpace($RefAr.$_) -or
                  ![string]::IsNullOrWhiteSpace($Ar.$_))) {
                    $_
                  }
                }
              }
              if ($PropList) {
                # Modify FileVantageRule
                @('id','rule_group_id').foreach{
                  # Update identifiers
                  Write-Log 'Edit-Item' ((('FileVantageRule',$_ -join '.') -join ': '),([PSCustomObject]@{
                    old=$Ar.$_;new=$RefAr.$_} | Format-List | Out-String).Trim() -join "`n")
                  Set-Property $Ar $_ $RefAr.$_
                }
                $Req = $Ar | Edit-FalconFileVantageRule @Param
                if ($Req) {
                  # Capture individual modified property results
                  @($PropList).foreach{ Add-Result Modified $Req FileVantageRule $_ $Ref.$_ $Req.$_ }
                } elseif ($Fail) {
                  # Capture failure to modify exclusion
                  Add-Result Failed $Ar FileVantageRule -Comment $Fail.exception.message -Log 'to modify'
                }
              } else {
                # Capture ignored result
                Add-Result Ignored $Ar FileVantageRule -Comment Identical
              }
            } else {
              # Add rules that don't exist at the bottom of the existing FileVantageRuleGroup
              $Precedence = $Ref.assigned_rules.precedence[-1]+1
              @('rule_group_id','precedence').foreach{
                Write-Log 'Edit-Item' (('FileVantageRule',$_ -join ': '),([PSCustomObject]@{old=$Ar.$_;new=if (
                  $_ -eq 'precedence') { $Precedence } else { $Ref.id }} | Format-List |
                  Out-String).Trim() -join "`n")
              }
              Set-Property $Ar rule_group_id $Ref.id
              Set-Property $Ar precedence $Precedence
              $Req = $Ar | New-FalconFileVantageRule @Param
              if ($Req) {
                # Capture individual modified property results
                @($PropList).foreach{ Add-Result Modified $Req FileVantageRule $_ $Ref.$_ $Req.$_ }
              } elseif ($Fail) {
                # Capture failure to modify exclusion
                Add-Result Failed $Ar FileVantageRule -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          }
        } elseif ($Ref -and $Item -eq 'FirewallGroup') {
          ## need to add FirewallRule evaluation
          #@('id','name','enabled','rule_ids').Where({$_ -ne 'id'}).foreach{
          #  [object]$Diff = if ($null -ne $Item.$_ -and $null -ne $Cid.$_) {
          #    # Compare properties that exist in both Modify and CID
          #    if ($p.Key -eq 'FirewallGroup' -and $_ -eq 'rule_ids') {
          #      if ($Item.rule_ids) {
          #       # Select FirewallRule from import using 'family' as 'id' value
          #       [object[]]$FwRule = foreach ($Rule in $Item.rule_ids) {
          #         $Config.FirewallRule.Import | Where-Object { $_.family -eq $Rule -and
          #           $_.deleted -eq $false }
          #       }
          #       if ($FwRule) {
          #         # Evaluate rules for modification
          #       }
          #      }
          #    }
          #  }
          #  # Output properties that differ, or are not present in CID
          #  if ($Diff -or ($null -ne $Item.$_ -and $null -eq $Cid.$_)) { $m.Add($_) }
          #}
          # Output items with properties to be modified and remove from Modify list
          #if ($m.Count -gt 1) { $Item | Select-Object $m }
        } elseif ($Ref -and $Item -eq 'FirewallLocation') {
          $Comp = Compare-FalconFirewallLocation -Reference $Ref -Object $Obj
          if ($Comp) {
            # Modify FirewallLocation when differences are found
            if ($Ref.id -ne $Obj.id) { Set-Property $Obj id $Ref.id }
            $Req = $Obj | Edit-FalconFirewallLocation @Param
            if ($Req) {
              # Capture individual modified property results
              @($Comp.PSObject.Properties.Name).foreach{ Add-Result Modified $Ref $Item $_ $Ref.$_ $Obj.$_ }
            } elseif ($Fail) {
              # Capture failure to modify FirewallLocation
              Add-Result Failed $Ref $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          } else {
            # Add ignored result
            Add-Result Ignored $Ref $Item -Comment Identical
          }
        } elseif ($Ref -and $Item -eq 'HostGroup') {
          # Modify HostGroup
          [string[]]$PropList = if ($Obj.description -ne $Ref.description) {
            # Check for modified 'description'
            'description'
          } elseif ($Obj.group_type -eq 'static' -and $Obj.assignment_rule -match '(device_id:|hostname:)') {
            # Compare hostname lists using 'assignment_rule' and output 'assignment_rule' if different
            [string[]]$ObjH = @($Obj.assignment_rule -split '(device_id:|hostname:)').Where({
              $_ -match '\[.+\]'}) -replace "^\[|'|\],?$" -split ','
            [string[]]$RefH = @($Ref.assignment_rule -split '(device_id:|hostname:)').Where({
              $_ -match '\[.+\]'}) -replace "^\[|'|\],?$" -split ','
            if (Compare-Object $ObjH $RefH) { 'assignment_rule' }
          }
          if ($PropList) {
            # Update identifier to match reference HostGroup
            if ($Obj.id -ne $Ref.id) { Update-Id $Obj $Ref $Item }
            $Req = $Obj | Edit-FalconHostGroup @Param
            if ($Req) {
              # Capture individual modified property results
              @($PropList).foreach{ Add-Result Modified $Req HostGroup $_ $Ref.$_ $Req.$_ }
            } elseif ($Fail) {
              # Capture failure to modify HostGroup
              Add-Result Failed $Obj HostGroup -Comment $Fail.exception.message -Log 'to modify'
            }
          } else {
            # Add ignored result
            Add-Result Ignored $Obj HostGroup -Comment Identical
          }
        } elseif ($Ref -and $Item -eq 'IoaGroup') {
          foreach ($r in @($Obj.rules).Where({$_.deleted -eq $false})) {
            # Check for matching rule in target environment, excluding deleted IoaRule
            $RefR = @($Ref.rules).Where({$_.deleted -eq $false}) |
              Where-Object -FilterScript (Write-SelectFilter $r IoaRule)
            if ($RefR) {
              Write-Log 'Edit-Item' (('IoaRule "{0}"' -f $r.name),([PSCustomObject]@{
                old=$r.instance_id;new=$RefR.instance_id} | Format-List | Out-String).Trim() -join "`n")
              [hashtable[]]$PropTable = if ($RefR) {
                # Evaluate IoaRule properties for changes
                @('disposition_id','enabled','pattern_severity').foreach{
                  if (Compare-Object $r.$_ $RefR.$_) { @{ property = $_; old = $RefR.$_; new = $r.$_ } }
                }
                foreach ($Fv in $r.field_values) {
                  # Evaluate 'field_values' as a Json string for each value under 'values'
                  $RefFv = @($RefR.field_values).Where({$_.name.Equals($Fv.name) -and $_.type.Equals($Fv.type)})
                  if ($RefFv) {
                    $ModFv = $false
                    foreach ($v in $RefFv.values) {
                      if ($ModFv -eq $false) {
                        $Old = $v | Select-Object label,value | ConvertTo-Json -Compress
                        $New = @($Fv.values).Where({$_.label.Equals($v.label)}) | Select-Object label,value |
                          ConvertTo-Json -Compress
                        if (Compare-Object $Old $New) {
                          # Capture 'field_values' as a simple Json for result output
                          @{
                            property = 'field_values'
                            old = "{$('"label":"{0}","values":[{1}]' -f $RefFv.label,$Old)}"
                            new = "{$('"label":"{0}","values":[{1}]' -f $Fv.label,$New)}"
                          }
                          $ModFv = $true
                        }
                      }
                    }
                  }
                }
              }
              if ($PropTable) {
                # Copy existing rule and modify properties and modify IoaRule
                $c = $RefR.PSObject.Copy()
                Set-Property $c rulegroup_id $Ref.id
                $Comment = if ($c.comment) { $c.comment } else { ($Comment,'modify_rule' -join ' ') }
                @($PropTable.property).foreach{ Set-Property $c $_ $r.$_ }
                $Req = Edit-FalconIoaRule -RuleUpdate $c -RuleGroupId $Ref.id -Comment $Comment @Param
                if ($Req) {
                  @($PropTable).foreach{
                    # Splat 'old', 'new' and 'property' from Edit to capture result
                    Add-Result Modified $c IoaRule @_ -Comment ('rulegroup_id',$c.rulegroup_id -join ':')
                  }
                } elseif ($Fail) {
                  # Capture failure to modify IoaRule
                  Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to modify'
                }
              } else {
                # Add output with updated 'rulegroup_id' to match 'platform'
                Set-Property $r rulegroup_id $Ref.id
                Add-Result Ignored $r IoaRule -Comment Identical
              }
            } else {
              # Add rules that don't exist at the bottom of the existing IoaGroup
              $Comment = if ($r.comment) { $r.comment } else { ($Comment,'create_rule' -join ' ') }
              $c = $r.PSObject.Copy()
              Set-Property $c rulegroup_id $Ref.id
              $Req = $c | New-FalconIoaRule @Param
              if ($Req) {
                # Update with current 'instance_id', capture result
                Set-Property $c instance_id $Req.instance_id
                Add-Result Created $c IoaRule -Comment ('rulegroup_id',$c.rulegroup_id -join ':')
              } elseif ($Fail) {
                # Capture failure to add IoaRule
                Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to create'
              }
              if ($c.enabled -eq $true) {
                # Enable rule to match import, capture result
                $Req = Edit-FalconIoaRule -RuleUpdate $c -RuleGroupId $Ref.Id -Comment ($Comment,
                  'modify_rule' -join ' ') @Param
                if ($Req) {
                  Add-Result Modified $c IoaRule enabled $false $c.enabled -Comment ('rulegroup_id',
                    $c.rulegroup_id -join ':')
                } elseif ($Fail) {
                  # Capture failure to enable IoaRule
                  Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to enable'
                }
              }
            }
          }
        } elseif ($Ref -and $Item -match '^(Ioa|Ml|Sv)Exclusion$') {
          # Verify 'applied_globally' and 'groups' values
          Update-Exclusion $Obj $Item $Config.HostGroup.Ref
          [string[]]$PropList = if ($Ref.is_descendant_process -ne $Obj.is_descendant_process) {
            'is_descendant_process'
          } elseif ($Ref.applied_globally -ne $Obj.applied_globally) {
            'applied_globally'
          } elseif ($Ref.applied_globally -eq $false) {
            if (($Obj.groups -and $Ref.groups -and (Compare-Object $Ref.groups.id $Obj.groups.id)) -or
            ($Obj.groups -and !$Ref.groups)) {
              # HostGroup identifiers don't match
              'groups'
            }
          }
          if ($PropList -and $Obj.groups) {
            # Update identifier with value from CID and modify exclusion
            if ($New.id -ne $Obj.id) {
              Write-Log 'Edit-Item' ($Item,([PSCustomObject]@{old=$Obj.id;new=$Ref.id} | Format-List |
                Out-String).Trim() -join "`n")
              Set-Property $Obj id $Ref.id
            }
            $Req = $Obj | & "Edit-Falcon$Item" @Param
            if ($Req) {
              @($PropList).foreach{
                # Capture modified properties
                if ($_ -eq 'groups') {
                  Add-Result Modified $Req $Item $_ ($Ref.$_.id -join ',') ($Req.$_.id -join ',')
                } else {
                  Add-Result Modified $Req $Item $_ $Ref.$_ $Req.$_
                }
              }
            } elseif ($Fail) {
              # Capture failure to modify exclusion
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          } elseif (!$PropList) {
            # Add ignored result
            Add-Result Ignored $Obj $Item -Comment Identical
          }
        } elseif ($Ref -and $Item -eq 'Script') {
          # Check Script properties
          [string[]]$PropList = if ($Obj.permission_type -ne $Ref.permission_type) {
            'permission_type'
          } elseif ($Obj.sha256 -ne $Ref.sha256) {
            'content'
          }
          if ($PropList) {
            # Update identifier with value from CID and modify Script
            Set-Property $Obj id $Ref.id
            # Modify Script
            $Req = $Obj | Edit-FalconScript @Param
            if ($Req) {
              @($PropList).foreach{
                if ($_ -eq 'content') {
                  # Exclude 'old_value' and 'new_value' for 'content'
                  Add-Result Modified $Obj Script content -Comment 'Uploaded content'
                } else {
                  # Capture individual modified property results
                  Add-Result Modified $Obj Script $_ $Ref.$_ $Obj.$_
                }
              }
            } elseif ($Fail) {
              # Capture failure to modify Script
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          } else {
            # Add ignored result
            Add-Result Ignored $Obj Script -Comment Identical
          }
        }
      }
    }
    function Edit-Policy {
      param(
        [PSCustomObject]$Obj,
        [string]$Item,
        [PSCustomObject]$Ref
      )
      $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
      if ($Obj) {
        # Update identifier to match reference policy
        if ($Item -eq 'DeviceControlPolicy') {
          $Edit = Compare-Setting $Obj $Ref $Item
          if ($Edit.setting.Count) {
            # Modify DeviceControlPolicy properties
            $ReqS = [PSCustomObject]$Edit.setting | Edit-FalconDeviceControlPolicy @Param
            if ($ReqS) {
              # Capture each modified property
              Compare-Setting $Req $ReqS $Item -Result
            } elseif ($Fail) {
              # Capture failure to modify Policy
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          }
          if ($Edit.exception.Count) {
            # Modify DeviceControlPolicy classes
            $ReqE = [PSCustomObject]$Edit.exception | Edit-FalconDeviceControlClass @Param
            if ($ReqE) {
              # Capture each modified property
              $Old = if ($ReqS) { $ReqS } else { $Ref }
              Compare-Setting $ReqE $Old $Item -Result
            } elseif ($Fail) {
              # Capture failure to modify Policy
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          }
        } elseif ($Item -eq 'FileVantagePolicy') {
          # Update policy identifier
          if ($Obj.id -ne $Ref.id) { Update-Id $Obj $Ref $Item }
          if ($Obj.exclusions) {
            foreach ($e in $Obj.exclusions) {
              # Check for existing matching exclusion
              $RefE = @($Ref.exclusions).Where({$_.name -eq $e.name})
              # Remove 'repeated' from imported exclusion when empty to prevent submission error
              if ($null -eq $e.repeated.PSObject.Properties.Name) { $e.PSObject.Properties.Remove('repeated') }
              if ($RefE) {
                [string[]]$Edit = @($e.PSObject.Properties.Name).Where({$_ -notmatch
                '^((policy_)?id|\w+_timestamp)$'}).foreach{
                  # Compare existing exclusion against import to find new or modified properties
                  if ($_ -eq 'repeated') {
                    foreach ($i in $e.repeated.PSObject.Properties.Name) {
                      # Check each sub-property under 'repeated'
                      if (!$RefE.repeated.$i -or $RefE.repeated.$i -ne $e.repeated.$i) { 'repeated' }
                    }
                  } elseif (!$RefE.$_ -or $e.$_ -ne $RefE.$_) {
                    $_
                  }
                } | Select-Object -Unique
                if ($Edit) {
                  @('id','policy_id').foreach{
                    # Update identifiers
                    Write-Log 'Edit-Policy' (('FileVantageExclusion',$_ -join ': '),([PSCustomObject]@{old=$e.id;
                      new=$RefE.$_} | Format-List | Out-String).Trim() -join "`n")
                    Set-Property $e $_ $RefE.$_
                  }
                  # Modify FileVantageExclusion
                  $Req = $e | Edit-FalconFileVantageExclusion @Param
                  if ($Req) {
                    @($Edit).foreach{
                      if ($_ -eq 'repeated') {
                        # Convert 'repeated' to a string and capture result
                        Add-Result Modified $Req FileVantageExclusion $_ ($RefE.$_ | Format-List |
                          Out-String).Trim() ($Req.$_ | Format-List | Out-String).Trim()
                      } else {
                        # Capture result
                        Add-Result Modified $Req FileVantageExclusion $_ $RefE.$_ $Req.$_
                      }
                    }
                  } elseif ($Fail) {
                    # Capture failure to modify FileVantageExclusion
                    Add-Result Failed $e FileVantageExclusion -Comment $Fail.exception.message -Log 'to modify'
                  }
                }
              } else {
                # Create FileVantageExclusion
                Write-Log 'Edit-Policy' (('FileVantageExclusion','policy_id' -join ': '),([PSCustomObject]@{
                  old=$e.id;new=$Obj.id} | Format-List | Out-String).Trim() -join "`n")
                Set-Property $e policy_id $Obj.id
                $Req = $e | New-FalconFileVantageExclusion @Param
                if ($Req) {
                  # Capture result
                  Add-Result Created $Req FileVantageExclusion
                } elseif ($Fail) {
                  # Capture failure to create FileVantageExclusion
                  Add-Result Failed $e FileVantageExclusion -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
          foreach ($g in @('host_groups','rule_groups')) {
            # Update identifiers and assign FileVantageRuleGroup and HostGroup to FileVantagePolicy
            if ($Obj.$g) {
              $Group = Update-GroupId $Obj.$g $Item $g
              if ($Group -and $Obj.$g) {
                Set-Property $Obj $g $Group
                Submit-Group $Item $g $Obj $Ref
              }
            }
          }
        } elseif ($Obj.settings) {
          if ($Item -eq 'FirewallPolicy') {
            if ($Obj.settings) {
              if ($Obj.id -ne $Ref.id) {
                # Update policy identifier
                Update-Id $Obj $Ref $Item
              }
              if ($Obj.settings.policy_id -ne $Ref.id) {
                # Update 'policy_id' under 'settings'
                Set-Property $Obj.settings policy_id $Ref.id
              }
              if ($Obj.settings.rule_group_ids) {
                # Update 'rule_group_ids'
                $Obj.settings.rule_group_ids = [string[]](
                  Update-GroupId $Obj.settings.rule_group_ids FirewallPolicy rule_group_ids)
              }
              if ((Compare-Setting $Obj $Ref $Item) -contains $true) {
                # Modify 'settings'
                $Req = $Obj.settings | Edit-FalconFirewallSetting @Param
                if ($Req) {
                  # Capture FirewallSetting result
                  Compare-Setting $Obj $Ref $Item -Result
                } elseif ($Fail) {
                  # Capture failure to modify FirewallPolicy
                  Add-Result Failed $Obj FirewallPolicy -Comment $Fail.exception.message -Log 'to modify'
                }
              } else {
                # Add 'ignored' result
                Add-Result Ignored $Obj FirewallPolicy -Comment Identical
              }
            }
          } else {
            $Edit = Compare-Setting $Obj $Ref $Item
            if ($Edit) {
              # Modify Policy and capture result
              if ($Obj.id -ne $Ref.id) { Update-Id $Obj $Ref $Item }
              $Req = & "Edit-Falcon$Item" -Id $Obj.id -Setting $Edit @Param
              if ($Req) {
                # Capture each modified property
                Compare-Setting (Compress-Object $Req $Item) $Ref $Item -Result
              } elseif ($Fail) {
                # Capture failure to modify Policy
                Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          }
        }
        # Update policy identifier for modifying 'groups' and 'enabled'
        if ($Obj.id -ne $Ref.id) { Update-Id $Obj $Ref $Item }
        if ($Item -eq 'PreventionPolicy') {
          if ($Obj.ioa_rule_groups) {
            # Update IoaGroup identifiers and assign to PreventionPolicy
            $Obj.ioa_rule_groups = Update-GroupId $Obj.ioa_rule_groups $Item ioa_rule_groups
            if ($Obj.ioa_rule_groups) { Submit-Group $Item ioa_rule_groups $Obj $Ref }
          } elseif ($Obj.name -match $PolicyDefault) {
            # Record that no changes were made for default policy when ioa_rule_groups are not present
            Add-Result Ignored $Obj $Item -Comment Identical
          }
        }
        if ($Obj.groups -and $Obj.name -notmatch $PolicyDefault) {
          # Assign HostGroup to non-default policy
          $Obj.groups = Update-GroupId $Obj.groups $Item groups
          if ($Obj.groups) { Submit-Group $Item groups $Obj $Ref }
        }
        if ($Obj.name -notmatch $PolicyDefault -and $Ref.enabled -ne $Obj.enabled) {
          # Enable or disable non-default policy
          [string]$Action = if ($Obj.enabled -eq $true) { 'enable' } else { 'disable' }
          Invoke-PolicyAction $Item $Action $Obj -Ref $Ref
        }
      }
    }
    function Find-Import {
      # Filter Import list and create Modify list
      foreach ($p in $Config.GetEnumerator().Where({$_.Key -notmatch $NoEnum -and $_.Value.Import})) {
        $Import = [System.Collections.Generic.List[PSCustomObject]]@()
        $Modify = [System.Collections.Generic.List[PSCustomObject]]@()
        foreach ($i in $p.Value.Import) {
          if ($i.deleted -eq $true) {
            # Ignore 'deleted' items
            Add-Result Ignored $i $p.Key -Comment Deleted
          } else {
            [string]$Platform = switch ($i) {
              # Check for platform value for log message
              { $_.platform } { $i.platform -join ',' }
              { $_.platforms} { $i.platforms -join ',' }
              { $_.platform_name } { $i.platform_name }
            }
            $Ref = if ($p.Value.Cid) {
              # Determine if matching item exists in target CID
              $Filter = Write-SelectFilter $i $p.Key
              if ($Filter) { $p.Value.Cid | Where-Object -FilterScript $Filter }
            }
            if ($Ref) {
              [string]$Comment = if ($p.Key -match 'Policy$' -and $i.name -match $PolicyDefault) {
                if ($UserDict.ValidDefault -notcontains $p.Key) {
                  # Ignore default policies that can't be modified
                  'Unmodifiable'
                } elseif (($UserDict.ModifyDefault -and $UserDict.ModifyDefault -notcontains $p.Key) -or
                !$UserDict.ModifyDefault) {
                  # Ignore default policies not specified under 'ModifyDefault'
                  'Not ModifyDefault'
                }
              } else {
                if ($UserDict.ValidExisting -notcontains $p.Key) {
                  # Ignore existing items that can't be modified
                  'Unmodifiable'
                } elseif (($UserDict.ModifyExisting -and $UserDict.ModifyExisting -notcontains $p.Key) -or
                !$UserDict.ModifyExisting) {
                  # Ignore items not specified under 'ModifyExisting'
                  'Not ModifyExisting'
                }
              }
              if ($Comment) {
                # Remove existing items from Import unless comment is specified
                Update-Id $i $Ref $p.Key
                Add-Result Ignored $i $p.Key -Comment $Comment
              } else {
                # Add existing items to Modify to analyze for modification
                $Modify.Add($i.PSObject.Copy())
                $Log = if ($Platform) {
                  'Modify: {0} {1} "{2}"' -f $Platform,$p.Key,$i.id
                } else {
                  'Modify: {0} "{1}"' -f $p.Key,$i.id
                }
                Write-Log 'Find-Import' $Log
              }
            } else {
              # Keep non-existent items under Import and add policies to Modify for changes post-creation
              if ($p.Key -match 'Policy$') { $Modify.Add($i.PSObject.Copy()) }
              $Name = Select-ObjectName $i $p.Key
              $Log = if ($Platform) {
                'Import: {0} {1} "{2}"' -f $Platform,$p.Key,$Name
              } else {
                'Import: {0} "{1}"' -f $p.Key,$Name
              }
              Write-Log 'Find-Import' $Log
              $Import.Add($i)
            }
          }
        }
        # Capture lists of items to be created and modified
        $p.Value['Import'] = $Import
        $p.Value['Modify'] = $Modify
      }
    }
    function Get-DcException {
      param(
        [PSCustomObject[]]$Obj
      )
      # Generate list of exceptions from a DeviceControlPolicy
      foreach ($i in ($Obj | Select-Object id,bluetooth_settings,@{l='usb_settings';e={if ($_.settings) {
      $_.settings } else { $_.usb_settings }}})) {
        foreach ($t in @('usb_settings','bluetooth_settings')) {
          @(@($i.$t.classes).Where({$_.exceptions}).exceptions).foreach{
            [PSCustomObject]$_ | Select-Object @{l='policy_id';e={$i.id}},@{l='type';e={$t}},id,class,
              vendor_id,vendor_name,product_id,product_name,serial_number,combined_id,action,match_method,
              description,minor_classes
          }
        }
      }
    }
    function Get-FromCid {
      # Retrieve items from CID
      foreach ($p in $Config.GetEnumerator().Where({$_.Value.Import})) {
        $Cid = [System.Collections.Generic.List[PSCustomObject]]@()
        $Param = @{ Detailed = $true; All = $true; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        if ($p.Key -eq 'FileVantagePolicy') {
          # Include exclusions when present in import
          if ($p.Value.exclusions) { $Param['Include'] = 'exclusions' }
          @($p.Value.Import.platform | Select-Object -Unique).foreach{
            # Retrieve FileVantagePolicy from target CID by 'platform'
            Write-Host ('[Import-FalconConfig] Retrieving {0} {1}...' -f $_,$p.Key)
            $RefP = & "Get-Falcon$($p.Key)" -Type $_ @Param
            if ($RefP) {
              # Return relevant properties for FileVantagePolicy, excluding default policies
              @(Compress-Object @($RefP).Where({$_.created_by -ne 'cs-cloud-provisioning' -and $_.name -notmatch
              $PolicyDefault}) $p.Key).foreach{
                $Cid.Add($_)
              }
            } elseif ($Fail) {
              # Notify of failure to retrieve from CID and remove
              Add-Result Failed -Type $p.Key -Log 'to retrieve'
            }
          }
        } elseif ($p.Key -eq 'FileVantageRuleGroup') {
          # Retrieve FileVantageRuleGroup from target CID by 'type' when present in Import
          @($p.Value.Import.type | Select-Object -Unique).foreach{
            Write-Host ('[Import-FalconConfig] Retrieving {0} {1}...' -f $_,$p.Key)
            $RefG = & "Get-Falcon$($p.Key)" -Type $_ @Param
            if ($RefG) {
              $CidG = foreach ($i in @($RefG).Where({$_.created_by -ne 'internal'})) {
                # Exclude FileVantageRuleGroup templates
                if ($i.assigned_rules.id -and @($p.Value.Import).Where({$_.type.Equals($i.type) -and
                $_.name.Equals($i.name)})) {
                  $CidR = @($i.assigned_rules.id).Where({![string]::IsNullOrWhiteSpace($_)})
                  if ($CidR) {
                    # Append rule content for matching imported FileVantageRuleGroup to 'assigned_rules'
                    Write-Host (
                      '[Import-FalconConfig] Retrieving FileVantageRule for {0} group "{1}"...' -f $i.type,$i.name)
                    Set-Property $i assigned_rules (Get-FalconFileVantageRule -RuleGroupId $i.id -Id $CidR)
                  }
                }
                $i
              }
              if ($CidG) { @(Compress-Object $CidG $p.Key).foreach{ $Cid.Add($_) } }
            } elseif ($Fail) {
              # Notify of failure to retrieve from CID and remove
              Add-Result Failed -Type $p.Key -Log 'to retrieve'
            }
          }
        } else {
          # Retrieve items from target CID
          Write-Host ('[Import-FalconConfig] Retrieving {0}...' -f $p.Key)
          $Ref = if ($p.Key -eq 'FirewallPolicy') {
            Get-FalconFirewallPolicy -Include settings @Param
          } else {
            & "Get-Falcon$($p.Key)" @Param
          }
          if ($Ref) {
            if ($p.Key -eq 'DeviceControlPolicy') {
              # Copy classes and exceptions to ExCid and ClassCid list for analysis and add to Cid
              $p.Value['ExCid'] = [System.Collections.Generic.List[PSCustomObject]]@()
              @(Get-DcException $Ref).foreach{ $p.Value.ExCid.Add($_) }
              @(Compress-Object $Ref $p.Key).foreach{ $Cid.Add($_) }
            } else {
              # Remove unnecessary properties and add to CID list
              @(Compress-Object $Ref $p.Key).foreach{ $Cid.Add($_) }
            }
          } elseif ($Fail) {
            # Notify of failure to retrieve
            Add-Result Failed -Type $p.Key -Log 'to retrieve'
          }
        }
        if ($Cid) {
          # Update identifier references
          Set-IdRef $Cid $p.Key -Update
          if ($Cid.groups) {
            # Update HostGroup with values from CID
            Set-IdRef $Cid.groups HostGroup -Update
          }
          if ($p.Key -eq 'PreventionPolicy' -and $Cid.ioa_rule_groups) {
            # Update IoaGroup with values from CID
            Set-IdRef $Cid.ioa_rule_groups IoaGroup -Update
          }
        }
        $p.Value['Cid'] = $Cid
      }
    }
    function Import-ConfigJson {
      param(
        [string]$String,
        [string[]]$List
      )
      $Output = @{}
      try {
        # Define valid files for import using Export-FalconConfig
        [string[]]$Valid = try {
          @((Get-Command Export-FalconConfig).Parameters.Select.Attributes.ValidValues + 'FirewallRule')
        } catch {
          throw 'Failed to retrieve valid import file types from "Export-FalconConfig" command!'
        }
        # Load Json files from archive
        $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
          Get-Content $String -AsByteStream
        } else {
          Get-Content $String -Encoding Byte -Raw
        }
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
        $FileStream = New-Object System.IO.MemoryStream
        $FileStream.Write($ByteStream,0,$ByteStream.Length)
        $ZipArchive = New-Object System.IO.Compression.ZipArchive($FileStream)
        foreach ($FullName in $ZipArchive.Entries.FullName) {
          # Convert Json and add to hashtable output
          $Filename = $ZipArchive.GetEntry($FullName)
          $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
          if ($Valid -contains $Item) {
            if (!$List -or ($List -and $List -contains $Item)) {
              # Filter to selected items when list is provided
              $Json = ConvertFrom-Json -InputObject (
                New-Object System.IO.StreamReader($Filename.Open())).ReadToEnd()
              if ($Json) {
                $Output[$Item] = @{ Import = [System.Collections.Generic.List[PSCustomObject]]@() }
                if ($Item -eq 'DeviceControlPolicy') {
                  # Create list of imported DeviceControlPolicy classes and exceptions
                  $Output.$Item['ExImp'] = [System.Collections.Generic.List[PSCustomObject]]@()
                  @(Get-DcException $Json).foreach{ $Output.$Item.ExImp.Add($_) }
                }
                # Add required properties from Json as Import
                @(Compress-Object $Json $Item).foreach{ $Output.$Item.Import.Add($_) }
                Write-Host ('[Import-FalconConfig] Successfully imported "{0}".' -f $Item)
              }
            } else {
              Write-Log 'Import-ConfigJson' ('Ignored "{0}"' -f $Filename)
            }
          } else {
            Write-Log 'Import-ConfigJson' ('Unexpected "{0}" ignored' -f $Filename)
          }
        }
        if ($FileStream) { $FileStream.Dispose() }
      } catch {
        Write-Host ('[Import-FalconConfig] Failed to import "{0}"!' -f $String)
        throw $_
      }
      if ($Output.Count) { $Output }
    }
    function Invoke-PolicyAction {
      param(
        [string]$Item,
        [string]$Action,
        [PSCustomObject]$Obj,
        [string]$Id,
        [PSCustomObject]$Ref
      )
      # Perform an action on a policy and output result
      $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
      if ($Id) { $Param['GroupId'] = $Id }
      if ($Obj.id) {
        $Req = if ($Item -eq 'FileVantagePolicy') {
          $Obj | Edit-FalconFileVantagePolicy @Param
        } else {
          $Obj.id | & "Invoke-Falcon$($Item)Action" -Name $Action @Param
        }
        if ($Action -match '^add-(host|rule)-group$') {
          if ($Req) {
            # Return to Submit-Group to capture result
            $Req
          } elseif ($Fail) {
            # Capture group assignment failure ## need to expand?
            Add-Result Failed $null HostGroup -Log 'to assign'
          }
        } elseif ($Action -match '^(enable|disable)$') {
          if ($Req.id) {
            # Capture enable result
            Add-Result Modified $Req $Item enabled $Ref.enabled $Obj.enabled
          } elseif ($Req) {
            # Capture enable result
            Add-Result Modified $Obj $Item enabled $Ref.enabled $Obj.enabled
          } elseif ($Fail) {
            # Capture enable failure
            Add-Result Failed $Req $Item enabled $Ref.enabled $Obj.enabled -Log 'to modify'
          }
        }
      }
    }
    function New-Group {
      param(
        [string]$Item,
        [string]$Comment
      )
      if ($Config.$Item.Import) {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        Write-Host ('[Import-FalconConfig] Creating {0}...' -f $Item)
        if ($Item -eq 'HostGroup') {
          # Create HostGroup
          for ($i=0; $i -lt $Config.$Item.Import.Count; $i+=10) {
            [PSCustomObject[]]$Group = @($Config.$Item.Import)[$i..($i+9)]
            $Req = $Group | New-FalconHostGroup @Param
            if ($Req) {
              @($Req).foreach{
                # Update identifier reference, capture result and add to 'Cid' list for modification reference
                Set-IdRef $_ $Item -Update
                Add-Result Created $_ $Item
                $Config.$Item.Cid.Add($_)
              }
              foreach ($g in $Group) {
                if (@($Req).Where({$_.name -eq $g.name -and $_.type -eq $g.type})) {
                  # Add created HostGroup to 'Modify' list for 'assignment_rule' updates
                  $Config.$Item.Modify.Add($g)
                }
              }
            } elseif ($Fail) {
              # Capture failure result
              @($Group).foreach{ Add-Result Failed $_ $Item -Comment $Fail.exception.message -Log 'to create' }
            }
          }
        } elseif ($Item -eq 'FileVantageRuleGroup') {
          foreach ($i in $Config.$Item.Import) {
            # Create FileVantageRuleGrop
            $Req = $i | New-FalconFileVantageRuleGroup @Param
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req.id
              Set-IdRef $Req $Item -Update
              Add-Result Created $Req $Item
            } elseif ($Fail) {
              # Capture creation failure
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
            }
            if ($i.assigned_rules) {
              foreach ($ar in $i.assigned_rules) {
                # Update identifier and create FileVantageRule
                Set-Property $ar rule_group_id $i.id
                $Req = $ar | New-FalconFileVantageRule @Param
                if ($Req) {
                  # Capture FileVantageRule result
                  Add-Result Created $Req FileVantageRule
                } elseif ($Fail) {
                  # Capture FileVantageRule creation failure
                  Add-Result Failed $ar FileVantageRule -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
        } elseif ($Item -eq 'FirewallGroup') {
          foreach ($i in $Config.$Item.Import) {
            [System.Collections.Generic.List[object]]$Rule = if ($i.rule_ids) {
              foreach ($r in $i.rule_ids) {
                # Select each FirewallRule from import using 'family' as 'id' value (excluding 'deleted')
                @($Config.FirewallRule.Import).Where({$_.family -eq $r -and $_.deleted -eq $false}).foreach{
                  # Trim rule names to 64 characters to meet API restriction
                  if ($_.name.Length -gt 64) { $_.name = ($_.name).SubString(0,63) }
                  $_
                }
              }
            }
            $Req = if ($Rule) {
              # Use collection of rules as 'Rule' and create FirewallGroup
              Write-Log 'New-Group' ('Selected {0} rules for {1} "{2}".' -f ($Rule | Measure-Object).Count,
                $Item,(Select-ObjectName $i $Item))
              $i | New-FalconFirewallGroup -Rule $Rule @Param
            } else {
              # Create FirewallGroup
              $i | New-FalconFirewallGroup @Param
            }
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req
              Set-IdRef $i $Item -Update
              Add-Result Created $i $Item
              if ($Rule) {
                foreach ($r in $Rule) {
                  # Update FirewallRule rule_group, convert 'family' to index, capture result
                  if ($r.rule_group -and $r.rule_group.id -and $r.rule_group.id -ne $i.id) {
                    $r.rule_group.id = $i.id
                  }
                  if ($r.family) { $r.family = 'precedence',($Rule.IndexOf($r) + 1) -join ':' }
                  Add-Result Created $r FirewallRule
                }
              }
            } elseif ($Fail) {
              # Capture FirewallGroup creation failure
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
              if ($Rule) {
                foreach ($r in $Rule) {
                  # Capture FirewallRule creation failure
                  if ($r.rule_group -and $r.rule_group.id -and $r.rule_group.id -ne $i.id) {
                    $r.rule_group.id = $i.id
                  }
                  if ($r.family) { $r.family = 'precedence',($Rule.IndexOf($r) + 1) -join ':' }
                  Add-Result Failed $r FirewallRule -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
          Clear-ConfigList FirewallRule Import
        } elseif ($Item -eq 'IoaGroup') {
          foreach ($i in $Config.$Item.Import) {
            # Create IoaGroup
            $Req = $i | New-FalconIoaGroup @Param
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req.id
              Set-IdRef $Req $Item -Update
              Add-Result Created $Req $Item
              if ($i.rules) {
                [string]$ArComment = ('rulegroup_id',$i.id -join ':')
                [object[]]$i.rules = foreach ($r in $i.rules) {
                  # Update IoaGroup identifier and append comment when not present
                  Set-Property $r rulegroup_id $Req.id
                  if (!$r.comment) { Set-Property $r comment ($Comment,'create_rule' -join ' ') }
                  # Create IoaRule inside IoaGroup
                  $Rule = $r | New-FalconIoaRule @Param
                  if ($Rule) {
                    # Add to output and set 'enable' status using imported IoaRule
                    Add-Result Created $Rule IoaRule -Comment $ArComment
                    if ($r.enabled -eq $true) { Set-Property $Rule enabled $r.enabled }
                    $Rule
                  } elseif ($Fail) {
                    # Capture IoaRule creation failure
                    Add-Result Failed $i IoaRule -Comment $Fail.exception.message -Log 'to create'
                  }
                }
                if ($i.rules.enabled -eq $true) {
                  # Enable IoaRule
                  if (!$i.comment) { Set-Property $i comment ($Comment,'enable_group' -join ' ') }
                  $EnR = $i | Edit-FalconIoaRule @Param
                  if ($EnR) {
                    @($EnR.rules).Where({$_.enabled -eq $true}).foreach{
                      # Capture IoaRule enable result
                      Add-Result Modified $_ IoaRule enabled $false $_.enabled -Comment $ArComment
                    }
                  } elseif ($Fail) {
                    # Capture IoaRule enable failure
                    Add-Result Failed $i IoaRule -Comment $Fail.exception.message -Log 'to enable'
                  }
                }
                if ($i.enabled -eq $true) {
                  # Enable IoaGroup
                  $EnG = Edit-FalconIoaGroup -Id $Req.id -Enabled $true @Param
                  if ($EnG) {
                    # Capture IoaGroup enable result
                    Add-Result Modified $Req $Item enabled $Req.enabled $EnG.enabled
                  } elseif ($Fail) {
                    # Capture IoaGroup enable failure
                    Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to enable'
                  }
                }
              }
            } elseif ($Fail) {
              # Capture creation failure for IoaGroup
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
            }
          }
        }
      }
    }
    function Select-ObjectName {
      param(
        [PSCustomObject]$Obj,
        [string]$Item
      )
      # Select a name to display in results and verbose output
      if ($Item -eq 'DeviceControlException') {
        switch ($Obj.match_method) {
          # Output DeviceControlPolicy exceptions properties for filtering or logging names
          'COMBINED_ID' { 'combined_id' }
          'VID' { 'vendor_id_decimal' }
          'VID_PID' { 'vendor_id_decimal','product_id_decimal' }
          'VID_PID_SERIAL' { 'vendor_id_decimal','product_id_decimal','serial_number' }
        }
      } elseif ($Obj.value) {
        if ($Obj.type) { $Obj.type,$Obj.value -join ':' } else { $Obj.value }
      } elseif ($Obj.precedence -and $Item -eq 'FileVantageRule') {
        $Obj.precedence
      } else {
        $Obj.name
      }
    }
    function Set-IdRef {
      param(
        [PSCustomObject[]]$Obj,
        [string]$Item,
        [switch]$Update
      )
      if ($Item -notmatch $NoEnum) {
        if ($Update) {
          foreach ($i in @($Obj).Where({$_.id -or $_.family})) {
            # Check for matching reference using selected properties and filter out matching 'new' identifier
            [string]$Id = if ($i.family) { $i.family } else { $i.id }
            $Filter = Write-SelectFilter $i $Item -Ref
            if ($Filter) {
              @($Config.$Item.Ref | Where-Object -FilterScript $Filter).Where({$_.new -ne $Id}).foreach{
                # Set 'new' identifier
                Set-Property $_ new $Id
                Write-Log 'Set-IdRef' ($Item,($_ | Format-List | Out-String).Trim() -join "`n")
              }
            }
          }
        } else {
          # Create sub-key for $Item when not present
          if ($Config.ContainsKey($Item) -eq $false) { $Config[$Item] = @{} }
          if ($Config.$Item.ContainsKey('Ref') -eq $false) {
            # Create empty identifier reference list when not present
            $Config.$Item['Ref'] = [System.Collections.Generic.List[PSCustomObject]]@()
          }
          foreach ($i in @($Obj).Where({$_.id -or $_.family})) {
            [string]$Id = if ($i.family) { $i.family } else { $i.id }
            if ($Id -and !@($Config.$Item.Ref).Where({$_.old.Equals($Id)})) {
              # Create new identifier reference
              $Ref = [PSCustomObject]@{ old = $Id; new = '' }
              @('name','os','type','value').foreach{
                # Capture listed properties
                if ($_ -eq 'os') {
                  # Convert 'platforms', 'platform_name', and 'platform' to 'os'
                  [string[]]$Value = if ($i.platforms) {
                    $i.platforms
                  } elseif ($i.platform_name) {
                    $i.platform_name
                  } elseif ($i.platform) {
                    $i.platform
                  }
                  if ($Value) { Set-Property $Ref $_ $Value }
                } else {
                  if ($i.$_) { Set-Property $Ref $_ $i.$_ }
                }
              }
              # Add 'cid' as reference property when HomeCid matches
              if ($HomeCid -and $i.cid -eq $HomeCid) { Set-Property $Ref cid $i.cid }
              $Config.$Item.Ref.Add($Ref)
              Write-Log 'Set-IdRef' ($Item,($Ref | Format-List | Out-String).Trim() -join "`n")
            } elseif ($Id) {
              # Log that existing reference was skipped
              Write-Log 'Set-IdRef' ($Item,('Ignored existing record "{0}"' -f $Id) -join "`n")
            }
          }
        }
      }
    }
    function Submit-Group {
      param(
        [string]$Item,
        [string]$Property,
        [PSCustomObject]$Obj,
        [PSCustomObject]$Ref
      )
      if ($Item -eq 'FileVantagePolicy') {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        if ($Property -eq 'rule_groups' -and $Obj.rule_groups) {
          # Assign FileVantageRuleGroup and capture result
          $Req = $Obj.rule_groups | Add-FalconFileVantageRuleGroup -PolicyId $Obj.id @Param
          if ($Req) {
            Add-Result Modified $Req $Item rule_groups ($Ref.rule_groups.id -join ',') (
              $Req.rule_groups.id -join ',')
          } elseif ($Fail) {
            # Capture FileVantageRuleGroup assignment failure
            Add-Result Failed $Obj FileVantagePolicy -Comment $Fail.exception.message -Log 'to assign'
          }
        } elseif ($Property -eq 'host_groups' -and $Obj.host_groups) {
          # Assign HostGroup and capture result
          $Req = $Obj.host_groups | Add-FalconFileVantageHostGroup -PolicyId $Obj.id @Param
          if ($Req) {
            Add-Result Modified $Req $Item host_groups ($Ref.host_groups.id -join ',') (
              $Req.host_groups.id -join ',')
          } elseif ($Fail) {
            # Capture HostGroup assignment failure
            Add-Result Failed $Obj FileVantagePolicy -Comment $Fail.exception.message -Log 'to assign'
          }
        }
      } else {
        # Assign group(s) to target object
        [string]$Action = if ($Property -eq 'ioa_rule_groups') { 'add-rule-group' } else { 'add-host-group' }
        [object[]]$Req = foreach ($g in $Obj.$Property) {
          # Assign each HostGroup or IoaGroup
          if ($Ref.$Property.id -notcontains $g.id) { Invoke-PolicyAction $Item $Action $Obj $g.id }
        }
        if ($Req -and $Req[-1].$Property.id) {
          # Capture latest assignment result if entire objects are returned
          Add-Result Modified $Req[-1] $Item $Property ($Ref.$Property.id -join ',') (
            $Req[-1].$Property.id -join ',')
        } elseif ($Req) {
          # Combine '$Property.$Id' values
          Add-Result Modified $Obj $Item $Property ($Ref.$Property -join ',') ($Req -join ',')
        }
      }
    }
    function Update-Exclusion {
      param(
        [PSCustomObject]$Obj,
        [string]$Item
      )
      if ($Obj.applied_globally -eq $true) {
        # Convert 'groups' to 'all' when 'applied_globally' is true
        Set-Property $Obj groups @('all')
        Write-Log 'Update-Exclusion' ('Changed "groups" for {0} "{1}" to "all"' -f $Item,$Obj.id)
      } elseif ($Obj.groups) {
        foreach ($i in $Obj.groups) {
          # Update assigned HostGroup with new identifiers or remove existing group
          $Ref = @($Config.HostGroup.Ref).Where({$_.old -eq $i.id})
          if ($Ref -and $i.id -ne $Ref.new) {
            Write-Log 'Update-Exclusion' "$((($Item,'groups' -join '.'),$Obj.id -join ': '),($i |
              Select-Object @{l='old';e={$i.id}},@{l='new';e={$Ref.new}} | Format-List |
              Out-String).Trim() -join "`n")"
            Set-Property $i id $Ref.new
          } elseif (!$Ref) {
            Write-Log 'Update-Exclusion' ('Removed group identifier "{0}" from {1} "{2}"' -f $i.id,$Item,$Obj.id)
          }
        }
      }
    }
    function Update-GroupId {
      param(
        [PSCustomObject[]]$Obj,
        [string]$Item,
        [string]$Type
      )
      # Determine which identifier reference to check by 'Type'
      [string]$Key = switch ($Type) {
        'groups' { 'HostGroup' }
        'host_groups' { 'HostGroup' }
        'ioa_rule_groups' { 'IoaGroup' }
        'rule_groups' { 'FileVantageRuleGroup' }
        'rule_group_ids' { 'FirewallGroup' }
      }
      foreach ($i in $Obj) {
        if ($i.id) {
          $Ref = if ($Item -eq 'FileVantagePolicy') {
            # Match by old 'id' for 'FileVantagePolicy'
            @($Config.$Key.Ref).Where({$_.old -eq $i.id})
          } else {
            $Filter = Write-SelectFilter $i $Key -Ref
            if ($Filter) { $Config.$Key.Ref | Where-Object -FilterScript $Filter }
          }
          if ($Ref.new -and $i.id -ne $Ref.new) {
            # Update group identifier
            Write-Log 'Update-GroupId' "$(($Item,$Type -join ': '),($i | Select-Object name,
              @{l='old';e={$i.id}},@{l='new';e={$Ref.new}} | Format-List | Out-String).Trim() -join "`n")"
            Set-Property $i id $Ref.new
          } elseif (!$Ref.new) {
            # Remove from groups value when new identifier is not available
            $Obj = @($Obj).Where({$_.id -ne $i.id})
            Write-Log 'Update-GroupId' ($Item,('Removed unmatched group "{0}"' -f $i.id) -join ': ')
          }
        } elseif ($i -match '^[a-fA-F0-9]{32}$') {
          # Use identifier reference to replace 'old' identifier values with 'new' values
          $New = @($Config.$Key.Ref).Where({$_.old -eq $i}).new
          if (!$New) {
            # Remove from array when new identifier is not available
            $Obj = @($Obj).Where({$_ -ne $i})
            Write-Log 'Update-GroupId' (($Item,$Type -join ': '),
              (' Removed unmatched group "{0}"' -f $i) -join "`n")
          } elseif ($New -and $i -ne $New) {
            # Update identifier
            $Obj = $Obj -replace $i,$New
            Write-Log 'Update-GroupId' "$(($Item,$Type -join ': '),($i | Select-Object @{l='old';e={$i}},
              @{l='new';e={$New}} | Format-List | Out-String).Trim() -join "`n")"
          }
        }
      }
      $Obj
    }
    function Update-Id {
      param(
        [PSCustomObject]$Obj,
        [PSCustomObject]$Ref,
        [string]$Item,
        [string]$Property
      )
      # Update identifier, or specified property with 'new' value
      if (!$Property) { $Property = 'id' }
      if ($Obj.$Property -ne $Ref.$Property) {
        Write-Log 'Update-Id' ($Item,([PSCustomObject]@{old=$Obj.$Property;new=$Ref.$Property} |
          Format-List | Out-String).Trim() -join "`n")
        Set-Property $Obj $Property $Ref.$Property
      }
    }
    function Update-SuPolicy {
      function Get-CurrentBuild ([string]$String,[string]$Platform) {
        if ($String -match '\|') {
          # Match by sensor build tag, replacing suffix with wildcard for cloud disparities
          if ($String -match '^n\|tagged\|\d{1,}$') { $String = $String -replace '\d{1,}$','*' }
          @($Config.SensorUpdatePolicy.Build).Where({$_.platform -eq $Platform -and $_.build -like "*|$String"}) |
            Select-Object build,sensor_version
        } elseif ($String) {
          # Check for exact sensor build version match
          @($Config.SensorUpdatePolicy.Build).Where({$_.platform -eq $Platform -and $_.build -eq $String}) |
            Select-Object build,sensor_version,stage
        } else {
          $null
        }
      }
      # Default timezone for use with 'scheduler'
      [string]$DefaultTz = 'Etc/Universal'
      foreach ($i in $Config.SensorUpdatePolicy.Import) {
        # Update sensor builds of imported policies with current build values
        if ($i -and $i.settings.build) {
          [string]$pBuild = if ($i.settings.build -match '|') {
            ($i.settings.build -split '\|',2)[-1]
          } else {
            $i.settings.build
          }
          $pNew = Get-CurrentBuild $pBuild $i.platform_name
          if ($pNew -and $pNew.build -ne $i.settings.build) {
            # Replace 'build' and related properties with current tagged version
            @('build','sensor_version','stage').foreach{
              Write-Log 'Update-SuPolicy' ($i.id,(' Changed "{0}" value from "{1}" to "{2}"' -f $_,$i.settings.$_,
                $pNew.$_) -join "`n")
              Set-Property $i.settings $_ $pNew.$_
            }
          } elseif (!$pNew) {
            # Strip build if build match is not available
            Write-Log 'Update-SuPolicy' ($i.id,(' Failed to match build "{0}"' -f $pBuild) -join "`n")
            Set-Property $i.settings build $null
          }
        }
        if ($i -and [string]::IsNullOrEmpty($i.settings.build)) {
          @('build','sensor_version','stage').foreach{
            # Remove properties to default to 'Sensor version updates off' when 'build' is empty
            Set-Property $i.settings $_ $null
            Write-Log 'Update-SuPolicy' ($i.id,(' Removed "{0}" value' -f $_) -join "`n")
          }
        }
        if ($i -and $i.settings.variants) {
          foreach ($v in $i.settings.variants) {
            # Update sensor variants with current available variant build values
            [string]$vBuild = if ($v.build -match '|') { ($v.build -split '\|',2)[-1] } else { $v.build }
            $vNew = Get-CurrentBuild $vBuild $v.platform
            if ($vNew -and $vNew.build -ne $v.build) {
              # Replace build with current tagged version
              Write-Log 'Update-SuPolicy' ($i.id,(' Changed {0} variant {1} "{2}" to "{3}"' -f $v.platform,$_,
                $v.build,$vNew.build) -join "`n")
              @('build','sensor_version','stage').foreach{ Set-Property $v $_ $vNew.$_ }
            } elseif (!$vNew) {
              # Strip build if match is not available
              Write-Log 'Update-SuPolicy' ($i.id,(' Failed to match {0} variant build "{1}"' -f $v.platform,
                $vBuild) -join "`n")
              Set-Property $v build $null
            }
            if ([string]::IsNullOrEmpty($v.build)) {
              # Strip build and sensor_version if 'build' is not present
              Set-Property $i.settings variants @($i.settings.variants).Where({$_.platform -ne $v.platform})
              Write-Log 'Update-SuPolicy' ($i.id,(' Removed "{0}" from variants' -f $v.platform) -join "`n")
            }
          }
        }
        if ($i -and !$i.settings.variants) {
          # Remove 'variants' if no variants are present for policy creation/modification
          $i.settings.PSObject.Properties.Remove('variants')
          Write-Log 'Update-SuPolicy' ($i.id,' Removed empty variants list' -join "`n")
        }
        if ($i.settings.scheduler) {
          if ([string]::IsNullOrEmpty($i.settings.scheduler.timezone)) {
            # Set default if no timezone is provided under 'scheduler'
            Set-Property $i.settings.scheduler timezone $DefaultTz
            Write-Log 'Update-SuPolicy' ($i.id,(' Set scheduler default timezone to {0}' -f $DefaultTz) -join "`n")
          }
        }
      }
    }
    function Write-SelectFilter {
      param(
        [PSCustomObject]$Obj,
        [string]$Item,
        [switch]$Ref
      )
      # Create FilterScript to select matching item
      if ($Obj) {
        if ($Item -eq 'DeviceControlException') {
          # Use 'match_method', 'action' and relevant 'name' properties to create filter
          [System.Collections.Generic.List[string]]$Select = @('match_method')
          @(Select-ObjectName $Obj $Item).foreach{ $Select.Add($_) }
          [scriptblock]::Create("($((@($Select).foreach{ '$_.{0} -eq "{1}"' -f $_,$Obj.$_}) -join ' -and '))")
        } else {
          [string[]]$Output = switch ($Obj) {
            { $_.platforms } {
              if ($Ref) {
                # Use 'os' to filter 'platforms' for an identifier reference
                "($((@($_.platforms).foreach{ '$_.os -contains "{0}"' -f $_ }) -join ' -and '))"
              } else {
                "($((@($_.platforms).foreach{ '$_.platforms -contains "{0}"' -f $_ }) -join ' -and '))"
              }
            }
            { $_.platform_name } {
              if ($Ref) {
                # Use 'os' to filter 'platform_name' for an identifier reference
                '$_.os -contains "{0}"' -f $_.platform_name
              } else {
                '$_.platform_name -eq "{0}"' -f $_.platform_name
              }
            }
            { $_.platform } {
              if ($Ref) {
                # Use 'os' to filter 'platform' for an identifier reference
                '$_.os -contains "{0}"' -f $_.platform
              } else {
                '$_.platform -eq "{0}"' -f $_.platform
              }
            }
            { $_.name } { '$_.name -eq "{0}"' -f $_.name }
            { $_.path } { '$_.path -eq "{0}"' -f $_.path }
            { $_.precedence } { '$_.precedence -eq "{0}"' -f $_.precedence }
            { $_.ruletype_id } { '$_.ruletype_id -eq "{0}"' -f $_.ruletype_id }
            { $_.type } { '$_.type -eq "{0}"' -f $_.type }
            { $_.value } { '$_.value -eq "{0}"' -f $_.value }
          }
          if ($Output) {
            # Add 'cid' if 'TargetCid' matches, then create FilterScript
            if ($HomeCid -and $Obj.cid -eq $HomeCid) { $Output += '$_.cid -eq "{0}"' -f $Obj.cid }
            [scriptblock]::Create(($Output -join ' -and '))
          } else {
            # Log when filter is not created
            Write-Log 'Write-SelectFilter' (
              'Unable to determine filter critera for "{0}" [{1}]' -f (Select-ObjectName $Obj $Item),$Item)
          }
        }
      }
    }
    [string]$ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
    [string]$NoEnum = '^(FirewallRule)$'
    [string]$OutputFile = Join-Path (Get-Location).Path "FalconConfig_$(
      (Get-Date -Format FileDateTime) -replace '\d{4}$',$null).csv"
    [regex]$PolicyDefault = '^(platform_default|Default Policy \((Linux|Mac|Windows)\))$'
    [string]$UaComment = ((Show-FalconModule).UserAgent,'Import-FalconConfig' -join ': ')
  }
  process {
    # Capture valid values for ModifyDefault and ModifyExisting
    $UserDict = @{}
    @('Default','Existing').foreach{
      $UserDict["Valid$_"] = @(
        (Get-Command Import-FalconConfig).Parameters."Modify$_".Attributes.ValidValues
      ).Where({$_ -ne 'All'})
    }
    # Capture user input for AssignExisting, ModifyDefault, ModifyExisting, and Select
    $PSBoundParameters.GetEnumerator().Where({!$_.Key.Equals('Path') -and $_.Value}).foreach{
      $UserDict[$_.Key] = $_.Value
    }
    # Update input to coincide with Select values
    Confirm-InputValue $UserDict
    if (!$ArchivePath) { throw "Failed to resolve '$($PSBoundParameters.Path)'." }
    # Attempt to retrieve CID using 'Get-FalconCcid' for evaluation
    [string]$HomeCid = try {
      Confirm-CidValue (Get-FalconCcid -EA 0)
    } catch {
      throw "Failed to retrieve target CID value. Verify 'Sensor Download: Read' permission."
    }
    # Import items from target archive
    $Config = Import-ConfigJson $ArchivePath $UserDict.Select
    if (!$Config) { throw "Failed to import configuration files!" }
    # Create identifier references for imported items
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Import})) {
      Set-IdRef $p.Value.Import $p.Key
      if ($p.Values.Import.groups -and !$Config.HostGroup.Import) {
        # Capture HostGroup identifiers when HostGroup was not imported
        Set-IdRef $p.Values.Import.groups HostGroup
      }
      if ($p.Key -eq 'PreventionPolicy' -and $p.Value.Import.ioa_rule_groups -and !$Config.IoaGroup.Import) {
        # Capture IoaGroup identifiers from PreventionPolicy when IoaGroup was not imported
        Set-IdRef $p.Value.Import.ioa_rule_groups IoaGroup
      }
    }
    # Modify imported SensorUpdatePolicy
    if ($Config.SensorUpdatePolicy.Import) {
      $Config.SensorUpdatePolicy['Build'] = try {
        # Retrieve current sensor builds
        Write-Host "[Import-FalconConfig] Retrieving current sensor builds for SensorUpdatePolicy..."
        Get-FalconBuild
      } catch {
        throw "Failed to retrieve current sensor builds. Verify 'Sensor update policies: Write' permission."
      }
      # Update SensorUpdatePolicy scheduler and current builds
      if ($Config.SensorUpdatePolicy.Build) { Update-SuPolicy }
    }
    # Add items from target CID to Config, filter Import, create Modify list
    Get-FromCid
    Find-Import
    # Create HostGroup
    if ($Config.HostGroup.Import) {
      New-Group HostGroup
      Clear-ConfigList HostGroup Import
    }
    # Create non-policy items
    foreach ($p in $Config.GetEnumerator().Where({$_.Key -notmatch 'Policy$' -and $_.Value.Import})) {
      if ($p.Key -match '^(Ioa|Ml|Sv)Exclusion$') {
        # Create IoaExclusion, MlExclusion, SvExclusion
        foreach ($i in $p.Value.Import) {
          if ($i.applied_globally -eq $false -and !$i.groups) {
            # Ignore exclusion, add to output
            Add-Result Ignored $i $p.Key -Comment 'applied_globally:false, groups:null'
          } else {
            # Verify required properties and values
            Update-Exclusion $i $p.Key
            if ($i.groups) {
              # Create exclusion
              @($i | & "New-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
                # Update identifier reference, capture result
                Add-Result Created $_ $p.Key
                Set-IdRef $_ $p.Key -Update
              }
              if ($Fail) { Add-Result Failed $i $p.Key -Log 'to create' -Comment $Fail.exception.message }
            }
          }
        }
      } elseif ($p.Key -eq 'FirewallLocation') {
        # Create FirewallLocation
        @($p.Value.Import).foreach{
          $i = $_ | New-FalconFirewallLocation -EA 0 -EV Fail
          if ($i) {
            # Capture result
            Add-Result Created $i $p.Key
          } elseif ($Fail) {
            # Capture failure
            Add-Result Failed $_ $p.Key -Log 'to create' -Comment ($Fail.exception.message -join ',')
          }
        }
      } elseif ($p.Key -match 'Group$') {
        # Create FileVantageRuleGroup, FirewallGroup (including FirewallRule), and IoaGroup
        New-Group $p.Key $UaComment
      } elseif ($p.Key -eq 'Ioc') {
        # Create Ioc
        @($p.Value.Import).Where({$_.applied_globally -eq $false -and $_.host_groups}).foreach{
          # Update 'host_groups' identifiers
          [string[]]$_.host_groups = Update-GroupId $_.host_groups $p.Key host_groups
          if (!$_.host_groups) {
            # Capture ignored result and remove from list to create
            Add-Result Ignored $_ $p.Key -Comment 'Unable to match Host Group(s)'
            [void]$p.Value.Import.Remove($_)
          }
        }
        do {
          foreach ($i in ($p.Value.Import | New-FalconIoc -EA 0 -EV Fail)) {
            if ($i.message_type -and $i.message) {
              # Add individual failure to output
              Add-Result Failed $i $p.Key -Log 'to create' -Comment ($i.message_type,$i.message -join ': ')
            } elseif ($i.type -and $i.value) {
              # Capture result and remove individual Ioc from remaining import list
              Add-Result Created $i $p.Key
              $p.Value.Import = @($p.Value.Import).Where({$_.type -ne $i.type -and $_.value -ne $i.value})
            }
          }
          if ($Fail) {
            @($p.Value.Import).foreach{
              # Capture full creation failure
              Add-Result Failed $_ $p.Key -Comment $Fail.exception.message -Log 'to create'
            }
          }
        } until ($Fail -or !$p.Value.Import)
      } elseif ($p.Key -eq 'Script') {
        # Create Script
        foreach ($i in $p.Value.Import) {
          @($i | & "Send-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
            Add-Result Created ($i | Select-Object name,platform) $p.Key
          }
          if ($Fail) { Add-Result Failed $i $p.Key -Comment $Fail.exception.message -Log 'to create' }
        }
      }
      if ($p.Key -notmatch $NoEnum) { Clear-ConfigList $p.Key Import }
    }
    # Create Policy
    foreach ($p in $Config.GetEnumerator().Where({$_.Key -match 'Policy$' -and $_.Value.Import})) {
      Write-Host "[Import-FalconConfig] Creating $($p.Key)..."
      [string[]]$Select = if ($p.Key -eq 'FileVantagePolicy') {
        'name','platform','description'
      } else {
        'name','platform_name','description'
      }
      for ($i=0;$i -lt $p.Value.Import.Count;$i+=100) {
        [PSCustomObject[]]$g = @($p.Value.Import | Select-Object $Select)[$i..($i+99)]
        @($g | & "New-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
          # Update identifier reference, capture result, add to CID list for comparison during modification step
          Set-IdRef $_ $p.Key -Update
          Add-Result Created $_ $p.Key
          $Config.($p.Key).Cid.Add((Compress-Object $_ $p.Key))
        }
        if ($Fail) {
          # Capture creation failure
          @($g).foreach{ Add-Result Failed $_ $p.Key -Comment $Fail.exception.message -Log 'to create' }
        }
      }
      Clear-ConfigList $p.Key Import
    }
    # Modify non-policy items
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Modify -and $_.Key -notmatch 'Policy$'})) {
      foreach ($m in $p.Value.Modify) { Edit-Item $m $p.Key $UaComment }
      Clear-ConfigList $p.Key Modify
    }
    # Modify Policy
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Modify -and $_.Key -match 'Policy$'})) {
      foreach ($m in $p.Value.Modify) {
        [PSCustomObject[]]$Cid = if ($m) {
          # Gather matching policy from CID
          $Config.($p.Key).Cid | Where-Object -FilterScript (Write-SelectFilter $m $p.Key)
        }
        if ($HomeCid -and @($Cid).Where({$_.cid -eq $HomeCid})) {
          # Filter by 'cid' if re-importing into source CID to remove inherited policies
          [PSCustomObject[]]$Cid = @($Cid).Where({$_.cid -eq $HomeCid})
        }
        if (($Cid | Measure-Object).Count -gt 1) {
          # Make no changes when more than one matching policy is found
          Add-Result Ignored $m $p.Key -Comment ('Multiple {0} named "{1}" present' -f $m.platform_name,$m.name)
        } elseif ($m -and $Cid) {
          # Modify policy by type
          Edit-Policy $m $p.Key $Cid $Config
        }
      }
      Clear-ConfigList $p.Key Modify
    }
  }
  end {
    if ($Config.Values.Result) {
      foreach ($i in (@($Config.Values.Result).Where({$_.action -eq 'Created' -and $_.type -match 'Policy$'}) |
      Select-Object -Property action,type,platform,name -Unique)) {
        if ($i.action -eq 'Created' -and @($Config.($i.type).Cid).Where({$_.name -notmatch $PolicyDefault -and
        $_.platform_name -eq $i.platform -and $_.name -ne $i.name})) {
          # Output precedence warning when existing Policy is found under each 'platform'
          if ($i.platform -eq 'all') {
            $PSCmdlet.WriteWarning(
              ('[Import-FalconConfig] Existing {0} found. Verify precedence!' -f $i.type))
          } else {
            $PSCmdlet.WriteWarning(
              ('[Import-FalconConfig] Existing {0} {1} found. Verify precedence!' -f $i.platform,$i.type))
          }
        }
      }
      foreach ($i in (@($Config.Values.Result).Where({$_.action -eq 'Modified' -and $_.type -match
      '^(FileVantage|Firewall)Policy$' -and $_.property -match '^rule_group(_id)?s$' -and $_.old_value}) |
      Select-Object -Property action,type,platform,name -Unique)) {
        # Output precedence warning when rule groups are assigned to policies with existing rule groups
        $PSCmdlet.WriteWarning(
          ('[Import-FalconConfig] {0} {1} "{2}" had existing "{3}". Verify precedence!' -f $i.platform,
            $i.type,$i.name,$i.property))
      }
      if (@($Config.Values.Result).Where({$_.action -eq 'Created' -and $_.type -eq 'FirewallLocation'}) -and
      $Config.FirewallLocation.Cid) {
        # Output precedence warning for existing 'FirewallLocation'
          $PSCmdlet.WriteWarning('[Import-FalconConfig] Existing FirewallLocation found. Verify precedence!')
      }
    }
    if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
  }
}