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
    [ValidateSet('DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup',
      'FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion','PreventionPolicy',
      'ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [Alias('Items')]
    [string[]]$Select,
    [Parameter(ParameterSetName='ExportItem')]
    [switch]$Force
  )
  begin {
    function Get-ItemContent ([string]$String) {
      # Request content for provided 'Item'
      Write-Host "[Export-FalconConfig] Exporting '$String'..."
      $ConfigFile = Join-Path $Location "$String.json"
      $Config = if ($String -match '^FileVantage(Policy|RuleGroup)$') {
        [string]$Filter = if ($String -eq 'FileVantagePolicy') {
          # Filter to user-created FileVantagePolicy
          '$_.created_by -ne "cs-cloud-provisioning" -and $_.name -notmatch "^Default Policy \((Linux|Mac|' +
            'Windows)\)$"'
        } else {
          # Filter to user-created FileVantageRuleGroup
          '$_.created_by -ne "internal"'
        }
        $Param = @{ Detailed = $true; All = $true }
        if ($String -eq 'FileVantagePolicy' ) { $Param['include'] = 'exclusions' }
        @((Get-Command "Get-Falcon$String").Parameters.Type.Attributes.ValidValues).foreach{
          # Retrieve FileVantagePolicy/RuleGroup for each 'Type'
          & "Get-Falcon$String" @Param -Type $_ 2>$null |
            Where-Object -FilterScript ([scriptblock]::Create($Filter))
        }
      } elseif ($String -match 'Policy$') {
        @('Windows','Mac','Linux').foreach{
          # Create policy exports in 'platform_name' order to retain precedence
          & "Get-Falcon$String" -Filter "platform_name:'$_'" -Detailed -All 2>$null
        }
      } else {
        & "Get-Falcon$String" -Detailed -All 2>$null
      }
      if ($Config) {
        if ($String -eq 'FirewallPolicy') {
          # Export firewall settings
          Write-Host "[Export-FalconConfig] Exporting 'FirewallSetting'..."
          $Setting = Get-FalconFirewallSetting -Id $Config.id 2>$null
          foreach ($i in $Setting) {
            ($Config | Where-Object { $_.id -eq $i.policy_id }).PSObject.Properties.Add((
              New-Object PSNoteProperty('settings',$i)
            ))
          }
        } elseif ($String -eq 'FileVantageRuleGroup') {
          # Update 'assigned_rules' with rule content inside FileVantage rule groups
          foreach ($i in $Config) {
            $RuleId = $i.assigned_rules.id | Where-Object { ![string]::IsNullOrWhiteSpace($_) }
            if ($RuleId) {
              Write-Host "[Export-FalconConfig] Exporting rules for $($i.type) group '$($i.name)'..."
              $i.assigned_rules = @(Get-FalconFileVantageRule -RuleGroupId $i.id -Id $RuleId)
            }
          }
        }
        # Export results to json file and output created file name
        try {
          ConvertTo-Json @($Config) -Depth 32 | Out-File $ConfigFile -Append
          $ConfigFile
        } catch {
          throw "Unable to write to '$((Get-Location).Path)'. Try 'Export-FalconConfig' in a new location."
        }
      }
    }
    # Get current location and set output archive path
    $Location = (Get-Location).Path
    $ExportFile = Join-Path $Location "FalconConfig_$(Get-Date -Format FileDateTime).zip"
  }
  process {
    $OutPath = Test-OutFile $ExportFile
    if ($OutPath.Category -eq 'WriteError' -and !$Force) {
      Write-Error @OutPath
    } else {
      if (!$Select) {
        # Use items in 'ValidateSet' when not provided
        [string[]]$Select = @((Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({ $_.Name -eq
          'ExportItem' }).Parameters.Where({ $_.Name -eq 'Select' }).Attributes.ValidValues).foreach{ $_ }
      }
      if ($Select -contains 'FileVantagePolicy' -and $Select -notcontains 'FileVantageRuleGroup') {
        # Force 'FileVantageRuleGroup' when exporting 'FileVantagePolicy' for 'rule_groups'
        [string[]]$Select = @($Select + 'FileVantageRuleGroup')
      }
      if ($Select -contains 'FirewallGroup') {
        # Force 'FirewallRule' when exporting 'FirewallGroup'
        [string[]]$Select = @($Select + 'FirewallRule')
      }
      if ($Select -match '^((Ioa|Ml|Sv)Exclusion|FileVantagePolicy|Ioc)$' -and $Select -notcontains 'HostGroup') {
        # Force 'HostGroup' when exporting exclusions or IOCs
        [string[]]$Select = @($Select + 'HostGroup')
      }
      # Retrieve results, export to Json and capture file name
      [string[]]$JsonFiles = foreach ($String in $Select) { ,(Get-ItemContent $String) }
      if ($JsonFiles -and $PSCmdlet.ShouldProcess($ExportFile,'Compress-Archive')) {
        # Archive Json exports with content and remove them when complete
        $Param = @{
          Path = (Get-ChildItem | Where-Object { $JsonFiles -contains $_.FullName -and $_.Length -gt 0 }).FullName
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

Anything that already exists will be ignored and no existing items will be modified unless the relevant switch
parameters are included.
.PARAMETER Path
FalconConfig archive path
.PARAMETER AssignExisting
Assign existing host groups with identical names to imported items
.PARAMETER ModifyDefault
Modify specified 'platform_default' policies to match import
.PARAMETER ModifyExisting
Modify existing specified items to match import
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
    [Alias('Force')]
    [switch]$AssignExisting,
    [ValidateSet('DeviceControlPolicy','FirewallPolicy','PreventionPolicy','ResponsePolicy','SensorUpdatePolicy')]
    [string[]]$ModifyDefault,
    [ValidateSet('DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup','FirewallPolicy',
      'HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion','PreventionPolicy','ResponsePolicy','Script',
      'SensorUpdatePolicy','SvExclusion')]
    [string[]]$ModifyExisting
  )
  begin {
    function Add-Result {
      # Create result object for CSV output
      param(
        [ValidateSet('Created','Modified','Ignored')]
        [string]$Action,
        [object]$Item,
        [string]$Type,
        [string]$Property,
        [string]$Old,
        [string]$New,
        [string]$Comment
      )
      $Obj = [PSCustomObject]@{
        time = Get-Date -Format o
        api_client_id = $Script:Falcon.ClientId
        type = $Type
        id = if ($Action -eq 'Ignored') {
          $null
        } elseif ($Item.instance_id) {
          $Item.instance_id
        } else {
          $Item.id
        }
        name = if ($Item.value) {
          if ($Item.type) { $Item.type,$Item.value -join ':' } else { $Item.value }
        } elseif ($Item.precedence -and $Type -eq 'FileVantageRule') {
          $Item.precedence
        } else {
          $Item.name
        }
        platform = if ($Item.platform) {
          if ($Item.platform -is [string[]]) { $Item.platform -join ',' } else { $Item.platform }
        } elseif ($Item.platforms) {
          $Item.platforms -join ','
        } elseif ($Item.platform_name) {
          $Item.platform_name
        } elseif ($Type -match '^FileVantageRule(Group)?$') {
          $Item.type
        } elseif ($Type -eq 'FileVantageExclusion' -and $Item.policy_id) {
          @($Config.FileVantagePolicy.PSObject.Properties.Value).Where({ $_.id -eq $Item.policy_id }).platform |
            Select-Object -Unique
        } else {
          $null
        }
        action = $Action
        property = $Property
        old_value = $Old
        new_value = $New
        comment = if ($Comment) {
          $Comment
        } elseif ($Item.rule_group_id -and $Item.id) {
          'rule_group_id',$Item.rule_group_id -join ':'
        } elseif ($Item.policy_id -and $Item.id) {
          'policy_id',$Item.policy_id -join ':'
        }
      }
      $Config.Result.Add($Obj)
      if ($Action -match '^(Created|Modified)$') {
        # Notify when items are created or modified
        [System.Collections.Generic.List[string]]$Notify = @('[Import-FalconConfig]',$Action)
        if ($Property) { $Notify.Add("'$Property' for") }
        if ($Obj.platform -and $Obj.platform -notmatch ',' -and $Type -ne 'FileVantageRule') {
          $Notify.Add($Obj.platform)
        }
        $Notify.Add($Type)
        if ($Type -eq 'FileVantageRule') {
          $Notify.Add("$($Obj.name) in '$(@($Config.Ids.FileVantageRuleGroup).Where({
            $_.new_id -eq $Item.rule_group_id }).name)'.")
        } elseif ($Type -eq 'FileVantageExclusion') {
          $Notify.Add("'$($Obj.name)' in '$(@($Config.Ids.FileVantagePolicy).Where({
            $_.new_id -eq $Item.policy_id }).name)'.")
        } else {
          $Notify.Add("'$($Obj.name)'.")
        }
        Write-Host ($Notify -join ' ')
      }
    }
    function Compare-ImportData ([string]$Item) {
      if ($Config.$Item.Cid) {
        $Platform = @{}
        @('platform','platform_name').foreach{
          if ($Config.$Item.Cid.$_) {
            @($Config.$Item.Cid.$_ | Select-Object -Unique).foreach{ $Platform[$_] = @{} }
          }
        }
        if ($Platform.Count -gt 0) {
          foreach ($Key in $Platform.Keys) {
            # Define properties for comparison between imported and existing items (by platform)
            @('Cid','Import').foreach{
              $Platform.$Key[$_] = @($Config.$Item.$_).Where({
                $_.platform -eq $Key -or $_.platform_name -eq $Key
              })
            }
            [string[]]$Available = ($Platform.$Key.Cid | Get-Member -MemberType NoteProperty |
              Select-Object -Unique).Name
            [string[]]$Compare = @('name','type','value').Where({ $Available -contains $_ })
            Write-Log 'Import-FalconConfig' "Evaluating $Key $Item using '$($Compare -join ',')'"
            $FilterScript = [scriptblock]::Create(
              (@($Compare).foreach{ "`$Platform.`$Key.Cid -notcontains `$_.$_" }) -join ' -and '
            )
            @($Platform.$Key.Import | Where-Object -FilterScript $FilterScript).foreach{
              # Capture items for import (by platform)
              Write-Log 'Import-FalconConfig' "Selecting '$(
                if ($_.value) {
                  if ($_.type) { $_.type,$_.value -join ':' } else { $_.value }
                } elseif ($_.precedence -and $Item -eq 'FileVantageRule') {
                  $_.precedence
                } else {
                  $_.name
                }
              )' for import"
              $_
            }
            if ($ModifyExisting -contains $Item) {
              # Capture (non-policy) items to modify
              $FilterScript = [scriptblock]::Create(
                (@($Compare).foreach{ "`$Platform.`$Key.Cid eq `$_.$_" }) -join ' -and '
              )
              @($Platform.$Key.Import | Where-Object -FilterScript $FilterScript).foreach{
                Write-Log 'Import-FalconConfig' "Selecting '$(
                  if ($_.value) {
                    if ($_.type) { $_.type,$_.value -join ':' } else { $_.value }
                  } elseif ($_.precedence -and $Item -eq 'FileVantageRule') {
                    $_.precedence
                  } else {
                    $_.name
                  }
                )' for modification"
                $Config.$Item.Modify.Add($_)
              }
            }
          }
        } else {
          # Define properties for comparison between imported and existing items
          [string[]]$Available = ($Config.$Item.Cid | Get-Member -MemberType NoteProperty |
            Select-Object -Unique).Name
          [string[]]$Compare = @('name','type','value').Where({ $Available -contains $_ })
          Write-Log 'Import-FalconConfig' "Evaluating $Item using '$($Compare -join ',')'"
          $FilterScript = [scriptblock]::Create(
            (@($Compare).foreach{ "`$Config.$($Item).Cid.$_ -notcontains `$_.$_" }) -join ' -and '
          )
          @($Config.$Item.Import | Where-Object -FilterScript $FilterScript).foreach{
            # Capture items for import
            Write-Log 'Import-FalconConfig' "Selecting '$(
              if ($_.value) {
                if ($_.type) { $_.type,$_.value -join ':' } else { $_.value }
              } elseif ($_.precedence -and $Item -eq 'FileVantageRule') {
                $_.precedence
              } else {
                $_.name
              }
            )' for import"
            $_
          }
          if ($ModifyExisting -contains $Item) {
            # Capture (non-policy) items to modify
            $FilterScript = [scriptblock]::Create((@($Compare).foreach{
              "`$Config.$($Item).Cid.$($_) -eq `$_.$($_)" }) -join ' -and ')
            @($Config.$Item.Import | Where-Object -FilterScript $FilterScript).foreach{
              Write-Log 'Import-FalconConfig' "Selecting '$(
                if ($_.value) {
                  if ($_.type) { $_.type,$_.value -join ':' } else { $_.value }
                } elseif ($_.precedence -and $Item -eq 'FileVantageRule') {
                  $_.precedence
                } else {
                  $_.name
                }
              )' for modification"
              $Config.$Item.Modify.Add($_)
            }
          }
        }
      } elseif ($Config.$Item.Import) {
        # Capture all items for import when none are present in target environment
        @($Config.$Item.Import)
      }
    }
    function Compare-Setting ([object]$New,[object]$Old,[string]$Type,[string]$Property,[switch]$Result) {
      if ($Type -match 'Policy$') {
        # Compare modified policy settings
        $NewArr = if ($New.prevention_settings) { $New.prevention_settings } else { $New.settings }
        $OldArr = if ($Old.prevention_settings) { $Old.prevention_settings } else { $Old.settings }
        if ($OldArr -or $Result) {
          foreach ($Item in $NewArr) {
            if ($Item.value.PSObject.Properties.Name -eq 'enabled') {
              if ($OldArr.Where({ $_.id -eq $Item.id }).value.enabled -ne $Item.value.enabled) {
                if ($Result) {
                  # Capture modified result for boolean settings
                  Add-Result Modified $New $Type $Item.id ($OldArr.Where({ $_.id -eq
                    $Item.id }).value.enabled) $Item.value.enabled
                } else {
                  # Output setting to be modified
                  $Item | Select-Object id,value
                }
              }
            } else {
              foreach ($Name in $Item.value.PSObject.Properties.Name) {
                if ($OldArr.Where({ $_.id -eq $Item.id }).value.$Name -ne $Item.value.$Name) {
                  if ($Result) {
                    # Capture modified result for sub-settings
                    Add-Result Modified $New $Type ($Item.id,$Name -join ':') (($OldArr | Where-Object {
                      $_.id -eq $Item.id }).value.$Name) $Item.value.$Name
                  } else {
                    # Output setting to be modified
                    $Item | Select-Object id,value
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
            $OldValue = ($Old.$Property | Where-Object { $_.name -eq $Name }).values | ConvertTo-Json -Compress
            $NewValue = ($New.$Property | Where-Object { $_.name -eq $Name }).values | ConvertTo-Json -Compress
            if ($NewValue -ne $OldValue) { Add-Result Modified $New $Type $Name $OldValue $NewValue }
          }
        } elseif ($Property) {
          if ($New.$Property -ne $Old.$Property) {
            Add-Result Modified $New $Type $Property $Old.$Property $New.$Property
          }
        } else {
          @($New.PSObject.Properties.Name).Where({ $_ -notmatch '^(id|comment)$' }).foreach{
            if ($New.$_ -ne $Old.$_) { Add-Result Modified $New $Type $_ $Old.$_ $New.$_ }
          }
        }
      }
    }
    function Compress-Property ([object]$Object) {
      # Remove unnecessary properties and values
      if ($Object.applied_globally -eq $true -and $Object.PSObject.Properties.Name -contains 'groups') {
        Set-Property $Object groups @('all')
      }
      if ($Object.prevention_settings.settings) {
        [object[]]$Object.prevention_settings = $Object.prevention_settings.settings | Select-Object id,value
      }
      if ($Object.settings.settings) {
        [object[]]$Object.settings = $Object.settings.settings | Select-Object id,value
      }
      @('groups','host_groups','ioa_rule_groups','policy_assignments','rule_group','rule_groups').foreach{
        if ($Object.$_.id) { [string[]]$Object.$_ = $Object.$_.id }
      }
      return $Object
    }
    function Import-ConfigData ([string]$FilePath) {
      # Load 'FalconConfig' archive into memory
      [hashtable]$Output = @{ Ids = @{}; Result = [System.Collections.Generic.List[object]]@() }
      $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
        Get-Content $FilePath -AsByteStream
      } else {
        Get-Content $FilePath -Encoding Byte -Raw
      }
      [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
      $FileStream = New-Object System.IO.MemoryStream
      $FileStream.Write($ByteStream,0,$ByteStream.Length)
      $ConfigArchive = New-Object System.IO.Compression.ZipArchive($FileStream)
      [string[]]$Msg = foreach ($FullName in $ConfigArchive.Entries.FullName) {
        # Import Json, exclude unnecessary properties, add to output and notify
        $Filename = $ConfigArchive.GetEntry($FullName)
        $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
        $Import = ConvertFrom-Json (New-Object System.IO.StreamReader($Filename.Open())).ReadToEnd()
        $Output[$Item] = @{ Import = $Import; Modify = [System.Collections.Generic.List[object]]@() }
        $Output.Ids[$Item] = [System.Collections.Generic.List[object]]@()
        $Item
      }
      if ($FileStream) { $FileStream.Dispose() }
      if ($Msg) { Write-Host "[Import-FalconConfig] Imported from $($FilePath): $($Msg -join ', ')." }
      $Output
    }
    function Invoke-CreateIoc ([object]$Object) {
      foreach ($i in ($Object.Value.Import | & "New-Falcon$($Object.Key)")) {
        if ($i.id) {
          # Track created Ioc
          Update-Id $i $Object.Key
          Add-Result Created $i $Object.Key
        } elseif ($i.type -and $i.value -and $i.message) {
          @($Object.Value.Import).Where({ $_.type -eq $i.type -and $_.value -eq $i.value }).foreach{
            # Ignore failed Ioc
            Add-Result Ignored $_ $Object.Key -Comment $i.message
          }
        }
        # Remove created and failed Ioc from 'Import' using 'id' value
        [string[]]$Remove = @($Object.Value.Import).Where({ $_.type -eq $i.type -and $_.value -eq $i.value }).id
        $Object.Value.Import = @($Object.Value.Import).Where({ $Remove -notcontains $_.id })
      }
      # Repeat until 'Import' is empty
      if ($Object.Value.Import) { Invoke-CreateIoc $Object }
    }
    function Invoke-PolicyAction ([string]$Type,[string]$Action,[string]$PolicyId,[string]$GroupId) {
      try {
        # Perform an action on a policy and output result
        if ($GroupId -and $PolicyId) {
          $PolicyId | & "Invoke-Falcon$($Type)Action" -Name $Action -GroupId $GroupId
        } elseif ($PolicyId) {
          $PolicyId | & "Invoke-Falcon$($Type)Action" -Name $Action
        }
      } catch {
        Write-Error $_
      }
    }
    function Submit-Group ([string]$Type,[string]$Property,[object]$Object,[object]$Cid) {
      if ($Type -eq 'FileVantagePolicy') {
        if ($Property -eq 'rule_groups' -and $Object.rule_groups) {
          # Assign missing 'rule_groups'
          foreach ($OldId in $Object.rule_groups) {
            # Update rule_groups with new identifier(s)
            $Object.rule_groups = $Object.rule_groups -replace $OldId,
              @($Config.Ids.FileVantageRuleGroup).Where({ $_.old_id -eq $OldId }).new_id
          }
          if ($Object.rule_groups) {
            # Filter to rule_groups that are missing
            [string[]]$Add = @($Object.rule_groups).Where({ $Cid.rule_groups -notcontains $_ -and
              ![string]::IsNullOrWhiteSpace($_) })
            if ($Add) {
              # Assign and capture result
              @(Add-FalconFileVantageRuleGroup -PolicyId $Object.id -Id $Add).foreach{
                Add-Result Modified $_ $Pair.Key rule_groups ($Cid.rule_groups -join ',') (
                  $_.rule_groups.id -join ',')
              }
              
            }
          }
        } elseif ($Property -eq 'host_groups' -and $Object.host_groups) {
          # Filter to host_groups that are missing
          [string[]]$Add = @($Object.host_groups).Where({ $Cid.host_groups -notcontains $_ })
          if ($Add) {
            # Assign and capture result
            @(Add-FalconFileVantageHostGroup -PolicyId $Object.id -Id $Add).foreach{
              Add-Result Modified $_ $Pair.Key host_groups ($Cid.host_groups -join ',') (
                $_.host_groups.id -join ',')
            }
          }
        }
      } else {
        # Assign group(s) to target object
        [string]$Invoke = if ($Property -eq 'ioa_rule_groups') { 'add-rule-group' } else { 'add-host-group' }
        $Req = foreach ($Id in $Object.$Property) {
          if ($Cid.$Property -notcontains $Id) { @(Invoke-PolicyAction $Type $Invoke $Object.id $Id).foreach{ $_ }}
        }
        if ($Req) {
          # Capture result
          Add-Result Modified $Req[-1] $Type $Property ($Cid.$Property -join ',') ($Req[-1].$Property.id -join ',')
        }
      }
    }
    function Update-Id ([object]$Item,[string]$Type) {
      if ($Config.Ids.$Type) {
        # Add 'new_id' to 'Ids'
        [string[]]$Compare = @('platform_name','platform','type','value','name').foreach{ if ($Item.$_) { $_ }}
        [string]$Filter = (@($Compare).foreach{ "`$_.$($_) -eq '$($Item.$_)'" }) -join ' -and '
        @($Config.Ids.$Type | Where-Object -FilterScript ([scriptblock]::Create($Filter))).foreach{
          $_.new_id = if ($Item.family) { $Item.family } else { $Item.id }
        }
      }
    }
    [string[]]$Allowed = (Get-Command Export-FalconConfig).Parameters.Select.Attributes.ValidValues
    [string]$ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
    [string]$OutputFile = Join-Path (Get-Location).Path "FalconConfig_$(Get-Date -Format FileDateTime).csv"
    [regex]$PolicyDefault = '^(platform_default|Default Policy \((Linux|Mac|Windows)\))$'
    [string]$UserAgent = (Show-FalconModule).UserAgent
    [string[]]$ValidModify = (Get-Command Import-FalconConfig).Parameters.ModifyExisting.Attributes.ValidValues
  }
  process {
    # Import configuration files and capture identifiers for comparison
    if (!$ArchivePath) { throw "Failed to resolve '$($PSBoundParameters.Path)'." }
    $Config = Import-ConfigData $ArchivePath
    @($Config.Keys).Where({ $_ -notmatch '^(Ids|FirewallRule|Result)$' }).foreach{
      if ($Allowed -notcontains $_) {
        throw "'$($_,'json' -join '.')' is not a valid Json file name. Ensure that all files within '$(
          $ArchivePath)' correspond with output from 'Export-FalconConfig' [$(($Allowed | ForEach-Object {
            "'$_'"
          }) -join ',')]."
      }
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Value.Import })) {
      foreach ($Import in $Pair.Value.Import) {
        # Create a record of identifiers within CID to compare with imports
        $Import = Compress-Property $Import
        @($Import | Select-Object name,platform,platforms,platform_name,type,value).foreach{
          $Id = if ($Import.family) { $Import.family } else { $Import.id }
          Set-Property $_ old_id $Id
          Set-Property $_ new_id $null
          $Config.Ids.($Pair.Key).Add($_)
        }
      }
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -notmatch '^(Ids|Result)$' })) {
      $Pair.Value['Cid'] = try {
        if ($Pair.Key -match '^FileVantage(Policy|RuleGroup)$') {
          [string]$Property = if ($Pair.Key -eq 'FileVantagePolicy') { 'platform' } else { 'type' }
          [string]$Filter = if ($Pair.Key -eq 'FileVantagePolicy') {
            # Filter to user-created FileVantagePolicy
            '$_.created_by -ne "cs-cloud-provisioning" -and $_.name -notmatch "' + $PolicyDefault + '"'
          } else {
            # Filter to user-created FileVantageRuleGroup
            '$_.created_by -ne "internal"'
          }
          $Param = @{ Detailed = $true; All = $true }
          if ($Pair.Key -eq 'FileVantagePolicy' -and $Config.($Pair.Key).Import.exclusions) {
            # Include 'exclusions' if present in imported policies
            $Param['include'] = 'exclusions'
          }
          @($Pair.Value.Import.$Property | Select-Object -Unique).foreach{
            # Retrieve FileVantagePolicy/RuleGroup for each 'Type' and update identifiers
            Write-Host "[Import-FalconConfig] Retrieving $_ '$($Pair.Key)'..."
            foreach ($i in (& "Get-Falcon$($Pair.Key)" @Param -Type $_ | Where-Object -FilterScript (
            [scriptblock]::Create($Filter)))) {
              if ($Pair.Key -eq 'FileVantageRuleGroup' -and $i.assigned_rules.id -and
              @($Pair.Value.Import).Where({ $_.type -eq $i.type -and $_.name -eq $i.name })) {
                # Update FileVantageRuleGroup 'assigned_rules' with rule content when matching import is present
                $RuleId = $i.assigned_rules.id | Where-Object { ![string]::IsNullOrWhiteSpace($_) }
                if ($RuleId) {
                  Write-Host "[Import-FalconConfig] Retrieving rules for $($i.type) group '$($i.name)'..."
                  $i.assigned_rules = Get-FalconFileVantageRule -RuleGroupId $i.id -Id $RuleId
                }
              }
              Update-Id $i $Pair.Key
              Compress-Property $i
            }
          }
        } else {
          # Retrieve existing items from CID and update identifiers
          Write-Host "[Import-FalconConfig] Retrieving '$($Pair.Key)'..."
          @(& "Get-Falcon$($Pair.Key)" -Detailed -All).foreach{
            Update-Id $_ $Pair.Key
            Compress-Property $_
          }
        }
      } catch {
        throw $_
      }
      if ($Pair.Key -match 'Policy$') {
        $Pair.Value.Import = foreach ($Policy in $Pair.Value.Import) {
          if (!($Config.($Pair.Key).Cid | Where-Object { $_.name -eq $Policy.name -and
          (($Policy.platform_name -and $_.platform_name -eq $Policy.platform_name) -or ($Policy.platform -and
          $_.platform -eq $Policy.platform)) })) {
            # Keep only missing policy items for each OS under 'Import'
            $Policy
            $Pair.Value.Modify.Add($Policy.PSObject.Copy())
          } else {
            # Add to relevant 'Modify' list or add result as 'Ignored'
            if ($Policy.name -match $PolicyDefault) {
              if ($ModifyDefault -contains $Pair.Key) {
                $Pair.Value.Modify.Add($Policy.PSObject.Copy())
              } else {
                Add-Result Ignored $Policy $Pair.Key -Comment NotModifyDefault
              }
            } elseif ($ModifyExisting -contains $Pair.Key) {
              $Pair.Value.Modify.Add($Policy.PSObject.Copy())
            } else {
              Add-Result Ignored $Policy $Pair.Key -Comment NotModifyExisting
            }
          }
        }
      } elseif ($Pair.Key -ne 'FirewallRule') {
        foreach ($Item in $Pair.Value.Import) {
          # Track 'Ignored' items for final output
          [string]$Comment = if ($Item.deleted -eq $true) {
            'Deleted'
          } elseif ($Item.type -and $Item.value -and @($Pair.Value.Cid).Where({ $_.type -eq $Item.type -and
          $_.value -eq $Item.value })) {
            'Exists'
          } elseif ($Item.type -and $Item.name -and @($Pair.Value.Cid).Where({ $_.type -eq $Item.type -and
          $_.name -eq $Item.name })) {
            'Exists'
          } elseif ($Item.value -and @($Pair.Value.Cid).Where({ $_.value -eq $Item.value })) {
            'Exists'
          } elseif ($Item.name -and @($Pair.Value.Cid).Where({ $_.name -eq $Item.name })) {
            'Exists'
          }
          if ($Comment -and $ModifyExisting -notcontains $Pair.Key) {
            # If 'Exists' but it could be modified, update comment
            if ($Comment -eq 'Exists' -and $ValidModify -contains $Pair.Key) { $Comment = 'NotModifyExisting' }
            Add-Result Ignored $Item $Pair.Key -Comment $Comment
          }
        }
        if ($Pair.Key -eq 'FileVantageRuleGroup') {
          $Pair.Value.Import = foreach ($i in $Pair.Value.Import) {
            if (!@($Pair.Value.Cid).Where({ $_.type -eq $i.type -and $_.name -eq $i.name })) {
              # Remove rule groups that will not be created from 'Import'
              $i
            } elseif ($ModifyExisting -contains $Pair.Key) {
              # Add rule groups for modification
              $Config.($Pair.Key).Modify.Add($i)
            }
          }
        } else {
          $Pair.Value.Import = Compare-ImportData $Pair.Key
        }
      }
      if ($Pair.Key -eq 'SensorUpdatePolicy' -and ($Pair.Value.Import -or $Pair.Value.Modify)) {
        # Retrieve available sensor build versions to update 'tags'
        [object[]]$BuildList = try {
          Write-Host "[Import-FalconConfig] Retrieving available sensor builds..."
          Get-FalconBuild
        } catch {
          throw "Failed to retrieve available sensor builds for '$(
            $Pair.Key)' import. Verify 'Sensor update policies: Write' permission."
        }
        foreach ($Item in @(@($Pair.Value.Import) + @($Pair.Value.Modify))) {
          # Update tagged builds with current tagged build versions
          if ($Item.settings.build -match '^\d+\|') {
            [string]$Tag = ($Item.settings.build -split '\|',2)[-1]
            # Replace 'latest' tagged build suffix digits with wildcard for imports into different clouds
            if ($Tag -match '^n|tagged|\d{1,}$') { $Tag = $Tag -replace '\d{1,}$','*' }
            $Current = @($BuildList).Where({ $_.build -like "*|$Tag" -and $_.platform -eq
              $Item.platform_name }).build
            if ($Current -and $Item.settings.build -ne $Current) {
              $Item.settings.build = $Current
              Write-Log 'Import-FalconConfig' "Updated build from '$($Item.settings.build)' to '$Current'"
            } elseif (!$Current) {
              Write-Log 'Import-FalconConfig' "Failed to match '$Tag' to current build for '$(
                $Item.platform_name)'"
            }
          }
          if ($Item.settings.variants) {
            # Update tagged 'variant' builds with current tagged build versions
            foreach ($Variant in @($Item.settings.variants | Where-Object { $_.build -match '^\d+\|' })) {
              $Tag = ($Variant.build -split '\|',2)[-1]
              $Current = ($BuildList | Where-Object { $_.build -like "*|$Tag" -and $_.platform -eq
                $Variant.platform }).build
              if ($Current -and $Variant.build -ne $Current) {
                $Variant.build = $Current
                Write-Log 'Import-FalconConfig' "Updated variant build from '$($Variant.build)' to '$Current'"
              } elseif (!$Current) {
                Write-Log 'Import-FalconConfig' "Failed to match '$Tag' to current build for variant '$(
                  $Variant.platform)'"
              }
            }
          }
        }
      }
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -eq 'HostGroup' -and $_.Value.Import })) {
      foreach ($HostGroup in ($Pair.Value.Import | & "New-Falcon$($Pair.Key)")) {
        # Create HostGroup to prepare for assignment
        Update-Id $HostGroup $Pair.Key
        Add-Result Created $HostGroup $Pair.Key
      }
      [void]$Pair.Value.Remove('Import')
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Value.Import -or $_.Value.Modify })) {
      # Update 'Import' and 'Modify' HostGroup ids
      @('Import','Modify').foreach{
        foreach ($Item in $Pair.Value.$_) {
          @('groups','host_groups').foreach{
            foreach ($OldId in $Item.$_) {
              [string]$NewId = @($Config.Ids.HostGroup).Where({ $_.old_id -eq $OldId }).new_id
              if ($NewId) {
                [string[]]$Item.$_ = $Item.$_ -replace $OldId,$NewId
                if ($NewId -ne $OldId) {
                  Write-Log 'Import-FalconConfig' ('Updated {0} "{1}" id "{2}" to "{3}"' -f $Pair.Key,$_,$OldId,
                    $NewId)
                }
              }
            }
          }
        }
      }
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -match 'Policy$' -and $_.Value.Import })) {
      @($Pair.Value.Import | & "New-Falcon$($Pair.Key)").foreach{
        # Create Policy
        Update-Id $_ $Pair.Key
        Add-Result Created $_ $Pair.Key
      }
      [void]$Pair.Value.Remove('Import')
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -ne 'FirewallRule' -and $_.Value.Import })) {
      if ($Pair.Key -eq 'FileVantageRuleGroup') {
        foreach ($Item in $Pair.Value.Import) {
          @($Item | & "New-Falcon$($Pair.Key)").foreach{
            # Create FileVantageRuleGroup
            Set-Property $Item id $_.id
            Update-Id $_ $Pair.Key
            Add-Result Created $_ $Pair.Key
          }
          if ($Item.assigned_rules) {
            foreach ($FvRule in $Item.assigned_rules) {
              # Update FileVantageRule with new RuleGroup identifier, create rule and notify
              $FvRule.rule_group_id = $Item.id
              @($FvRule | New-FalconFileVantageRule).foreach{ Add-Result Created $_ FileVantageRule }
            }
          }
        }
      } elseif ($Pair.Key -eq 'FirewallGroup') {
        foreach ($Item in $Pair.Value.Import) {
          [object]$FwGroup = $Item | Select-Object name,enabled,description,comment,rule_ids,platform
          if ($FwGroup) {
            if ($FwGroup.rule_ids) {
              # Select FirewallRule from import using 'family' as 'id' value
              [object[]]$Rules = foreach ($Id in $FwGroup.rule_ids) {
                $Config.FirewallRule.Import | Where-Object { $_.family -eq $Id -and $_.deleted -eq $false }
              }
              @($Rules).foreach{
                # Trim rule names to 64 characters and use 'rules' as 'rule_ids'
                if ($_.name.length -gt 64) { $_.name = ($_.name).SubString(0,63) }
              }
              if ($Rules) {
                Set-Property $FwGroup rules $Rules
                [void]$FwGroup.PSObject.Properties.Remove('rule_ids')
              }
            }
            @($FwGroup | & "New-Falcon$($Pair.Key)").foreach{
              # Create FirewallGroup
              Set-Property $FwGroup id $_
              Update-Id $FwGroup $Pair.Key
              Add-Result Created $FwGroup $Pair.Key
            }
          }
        }
      } elseif ($Pair.Key -eq 'IoaGroup') {
        foreach ($Item in $Pair.Value.Import) {
          # Create IoaGroup
          [object]$IoaGroup = $Item | & "New-Falcon$($Pair.Key)"
          if ($IoaGroup) {
            Update-Id $IoaGroup $Pair.Key
            Add-Result Created $IoaGroup $Pair.Key
            if ($Item.rules) {
              # Create IoaRule
              [object[]]$IoaGroup.rules = foreach ($Rule in $Item.rules) {
                $Rule.rulegroup_id = $IoaGroup.id
                $Req = try { $Rule | New-FalconIoaRule } catch { Write-Error $_ }
                if ($Req) {
                  Add-Result Created $Req IoaRule
                  if ($Req.enabled -eq $false -and $Rule.enabled -eq $true) { $Req.enabled = $true }
                  $Req
                }
              }
              if ($IoaGroup.rules.enabled -eq $true) {
                @($IoaGroup | Edit-FalconIoaRule).foreach{
                  @($_.rules).Where({ $_.enabled -eq $true }).foreach{
                    # Enable IoaRule
                    Add-Result Modified $_ IoaRule enabled $false $_.enabled
                  }
                }
              }
            }
            if ($Item.enabled -eq $true -and $IoaGroup.enabled -ne $true) {
              @(& "Edit-Falcon$($Pair.Key)" -Id $IoaGroup.id -Enabled $true).foreach{
                # Enable IoaGroup
                Add-Result Modified $Item $Pair.Key enabled $false $_.enabled
              }
            }
          }
        }
      } elseif ($Pair.Key -eq 'Ioc') {
        # Create Ioc
        Invoke-CreateIoc $Pair
      } elseif ($Pair.Key -eq 'Script') {
        foreach ($Item in $Pair.Value.Import) {
          # Create Script
          @($Item | & "Send-Falcon$($Pair.Key)").foreach{
            Add-Result Created ($Item | Select-Object name,platform) $Pair.Key
          }
        }
      } elseif ($Pair.Key -match '^((Ioa|Ml|Sv)Exclusion)$') {
        foreach ($Item in $Pair.Value.Import) {
          # Create Exclusion
          @($Item | & "New-Falcon$($Pair.Key)").foreach{
            Update-Id $_ $Pair.Key
            Add-Result Created $_ $Pair.Key
          }
        }
      }
      [void]$Pair.Value.Remove('Import')
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -notmatch 'Policy$' -and $_.Value.Modify })) {
      if ($Pair.Key -eq 'FileVantageRuleGroup') {
        foreach ($Group in $Pair.Value.Modify) {
          $CidGroup = @($Config.($Pair.Key).Cid).Where({ $_.type -eq $Group.type -and $_.name -eq $Group.name })
          if ($CidGroup) {
            foreach ($Rule in $Group.assigned_rules) {
              $CidRule = @($CidGroup.assigned_rules).Where({ $_.type -eq $Rule.type -and $_.name -eq $Rule.name })
              if ($CidRule) {
                # Evaluate and update each FileVantageRule when required
                [string[]]$Modified = @($Rule.PSObject.Properties.Name).Where({ $_ -notmatch
                '^(type|(rule_group_)?id)$' }).foreach{
                  if (!$CidRule.$_ -or $CidRule.$_ -ne $Rule.$_) {
                    if (($_ -eq 'content_files' -and ![string]::IsNullOrWhiteSpace($CidRule.$_) -or
                    ![string]::IsNullOrWhiteSpace($Rule.$_)) -or $_ -ne 'content_files') {
                      $_
                    }
                  }
                }
                if ($Modified) {
                  @('id','rule_group_id').foreach{ $Rule.$_ = $CidRule.$_ }
                  $Req = $Rule | Edit-FalconFileVantageRule
                  if ($Req) {
                    @($Modified).foreach{ Add-Result Modified $Req FileVantageRule $_ $CidRule.$_ $Req.$_ }
                  }
                }
              } else {
                # Add rules that don't exist at the bottom of the existing FileVantageRuleGroup
                $Rule.rule_group_id = $CidGroup.id
                $Rule.precedence = $CidGroup.assigned_rules.precedence[-1] + 1
                $Req = $Rule | New-FalconFileVantageRule
                if ($Req) { Add-Result Created $Req FileVantageRule }
              }
            }
            if (!$Modified -and $Rule.group_id -ne $CidGroup.id) {
              # Add 'Ignored' result for unmodified FileVantageRuleGroup
              Add-Result Ignored $Group $Pair.Key -Comment Identical
            }
          }
        }
      } else {
        [string[]]$Select = switch ($Pair.Key) {
          # Select required properties for comparison (other than 'id')
          'FirewallGroup' { 'name','enabled','rule_ids' }
          'HostGroup' { 'group_type','name','assignment_rule' }
          'IoaGroup' { 'enabled','name','platform','rules' }
          'IoaExclusion' { 'name','pattern_id','pattern_name','cl_regex','ifn_regex','groups','applied_globally' }
          'Ioc' {
            'applied_globally','action','deleted','expiration','host_groups','mobile_action','platforms',
            'severity','tags','type','value'
          }
          'MlExclusion' { 'value','excluded_from','groups','applied_globally' }
          'Script' { 'platform','permission_type','name','content' }
          'SvExclusion' { 'value','groups','applied_globally' }
        }
        if ($Select) {
          [object[]]$EditList = foreach ($Item in ($Pair.Value.Modify | Select-Object @($Select + 'id'))) {
            # Compare each 'Modify' item against CID (excluding non-dynamic HostGroup)
            [string[]]$Compare = @('name','type','value').foreach{ if ($Select -contains $_) { $_ }}
            [string]$Filter = (@($Compare).foreach{ "`$_.$($_) -eq `$Item.$($_)" }) -join ' -and '
            [object]$Cid = $Config.($Pair.Key).Cid | Select-Object $Select | Where-Object -FilterScript (
              [scriptblock]::Create($Filter))
            if ($Cid) {
              [System.Collections.Generic.List[string]]$Modify = @('id')
              @($Select).Where({ $_ -ne 'id' }).foreach{
                [object]$Diff = if ($null -ne $Item.$_ -and $null -ne $Cid.$_) {
                  # Compare properties that exist in both 'Modify' and CID
                  if ($Pair.Key -eq 'FirewallGroup' -and $_ -eq 'rule_ids') {
                    <#
                    if ($Item.rule_ids) {
                      # Select FirewallRule from import using 'family' as 'id' value
                      [object[]]$FwRule = foreach ($Rule in $Item.rule_ids) {
                        $Config.FirewallRule.Import | Where-Object { $_.family -eq $Rule -and
                          $_.deleted -eq $false }
                      }
                      if ($FwRule) {
                        # Evaluate rules for modification
                      }
                    }
                    #>
                  } elseif ($Pair.Key -eq 'IoaGroup' -and $_ -eq 'rules') {
                    foreach ($Rule in $Item.$_) {
                      # Evaluate each IoaRule
                      [object]$CidRule = $Cid.$_ | Where-Object { $_.ruletype_id -eq $Rule.ruletype_id -and
                        $_.name -eq $Rule.name -and $Rule.deleted -ne $true }
                      [string[]]$RuleDiff = if ($CidRule) {
                        @('enabled','pattern_severity','action_label').foreach{
                          if (Compare-Object $Rule.$_ $CidRule.$_) { $_ }
                        }
                        foreach ($FieldValue in $Rule.field_values) {
                          # Evaluate 'field_value' as a Json string for each IoaRule
                          [object]$CidFieldValue = $CidRule.field_values | Where-Object {
                            $_.name -eq $FieldValue.name -and $_.type -eq $FieldValue.type }
                          if ($CidFieldValue) {
                            if (Compare-Object ($FieldValue.values | ConvertTo-Json) ($CidFieldValue.values |
                            ConvertTo-Json)) {
                              'field_values'
                            }
                          }
                        }
                      }
                      if ($RuleDiff) {
                        # Copy existing rule and modify properties
                        [object]$RuleEdit = $CidRule.PSObject.Copy()
                        @($RuleDiff).foreach{ $RuleEdit.$_ = $Rule.$_ }
                        @(Edit-FalconIoaRule -RuleUpdate $RuleEdit -RuleGroupId $Item.id).foreach{
                          # Capture result for each updated setting against original
                          @($RuleDiff).foreach{ Compare-Setting $RuleEdit $CidRule IoaRule $_ -Result }
                        }
                      }
                    }
                  } else {
                    Compare-Object $Item.$_ $Cid.$_
                  }
                }
                # Output properties that differ, or are not present in CID
                if ($Diff -or ($null -ne $Item.$_ -and $null -eq $Cid.$_)) { $Modify.Add($_) }
              }
              # Output items with properties to be modified and remove from 'Modify' list
              if ($Modify.Count -gt 1) { $Item | Select-Object $Modify }
            }
          }
          if ($EditList) {
            foreach ($Edit in $EditList) {
              # Update with current 'id' and 'comment' when appropriate
              Set-Property $Edit id ($Config.Ids.($Pair.Key) | Where-Object { $_.old_id -eq $Edit.id }).new_id
              if ($Pair.Key -ne 'HostGroup') {
                Set-Property $Edit comment ($UserAgent,"Import-FalconConfig" -join ': ')
              }
            }
            if ($Pair.Key -eq 'FirewallGroup') {
              [hashtable[]]$DiffOp = @($EditList).foreach{
                # Create 'DiffOperations' for FirewallGroup changes
                if ($null -ne $_.enabled) { @{ op = 'replace'; path = "/enabled"; value = $_.enabled }}
              }
              if ($DiffOp) {
                # Modify FirewallGroup
                $Req = $EditList | Edit-FalconFirewallGroup -DiffOperation $DiffOp
                if ($Req) {
                  Compare-Setting $Item ($Config.($Pair.Key).Cid | Where-Object { $_.id -eq
                    $Item.id }) $Pair.Key -Result
                }
              }
            } else {
              foreach ($Item in ($EditList | & "Edit-Falcon$($Pair.Key)")) {
                foreach ($Result in ($EditList | Where-Object { $_.id -eq $Item.id })) {
                  @($Result.PSObject.Properties.Name).Where({ $_ -ne 'id' -and $_ -ne 'comment' }).foreach{
                    # Modify item and capture result
                    Compare-Setting $Item ($Config.($Pair.Key).Cid | Where-Object { $_.id -eq
                      $Item.id }) $Pair.Key $_ -Result
                  }
                }
              }
            }
          }
          foreach ($Item in $Pair.Value.Modify) {
            if (($EditList -and $EditList.id -notcontains $Item.id) -or !$EditList) {
              # Record result for items that don't need modification
              [string]$Comment = if ($Pair.Key -eq 'HostGroup' -and $Item.group_type -ne 'dynamic') {
                'Static'
              } else {
                'Identical'
              }
              Add-Result Ignored $Item $Pair.Key -Comment $Comment
            }
          }
        }
      }
      [void]$Pair.Value.Remove('Modify')
    }
    foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -match 'Policy$' -and $_.Value.Modify })) {
      foreach ($Policy in $Pair.Value.Modify) {
        # Update policy with current id value and use CID value for comparison
        [string]$Policy.id = @($Config.Ids.($Pair.Key)).Where({ $_.name -eq $Policy.name -and
          $_.platform_name -eq $Policy.platform_name }).new_id
        [object]$Cid = @($Config.($Pair.Key).cid).Where({ $_.id -eq $Policy.id })
        if ($Policy.id -and $Pair.Key -eq 'FirewallPolicy') {
          if ($Policy.settings.policy_id) { $Policy.settings.policy_id = $Policy.id }
          foreach ($Id in $Policy.rule_group_ids) {
            # Update 'rule_group_ids' with new id values
            [object]$Group = $Config.Ids.FirewallGroup | Where-Object { $_.old_id -eq $Id }
            if ($Group -and $Policy.rule_group_ids -contains $Id) {
              [string[]]$Policy.rule_group_ids = $Policy.rule_group_ids -replace $Id,$Group.new_id
            }
          }
          if ($Policy.settings) {
            # Apply FirewallSetting
            @($Policy.settings | Edit-FalconFirewallSetting).foreach{
              Set-Property $Policy settings $Policy.settings
            }
          }
        } elseif ($Policy.id -and $Policy.prevention_settings -or $Policy.settings) {
          # Compare Policy settings
          $Setting = Compare-Setting $Policy $Cid $Pair.Key
          if ($Setting) {
            try {
              # Modify Policy
              @(& "Edit-Falcon$($Pair.Key)" -Id $Policy.id -Setting $Setting).foreach{
                Compare-Setting (Compress-Property $_) $Cid $Pair.Key -Result
              }
            } catch {
              Write-Error $_
            }
          }
        }
        if ($Policy.id -and $Policy.name -notmatch $PolicyDefault) {
          if ($Pair.Key -eq 'FileVantagePolicy') {
            if ($Policy.exclusions) {
              foreach ($Exclusion in $Policy.exclusions) {
                # Check for existing matching exclusion
                $Existing = @($Cid.exclusions).Where({ $_.name -eq $Exclusion.name })
                if ($null -eq $Exclusion.repeated.PSObject.Properties.Name) {
                  # Remove 'repeated' from imported exclusion when empty to prevent submission error
                  $Exclusion.PSObject.Properties.Remove('repeated')
                }
                if ($Existing) {
                  [string[]]$Modified = @($Exclusion.PSObject.Properties.Name).Where({ $_ -notmatch
                  '^((policy_)?id|\w+_timestamp)$' }).foreach{
                    # Compare existing exclusion against import to find new or modified properties
                    if ($_ -eq 'repeated') {
                      foreach ($i in $Exclusion.repeated.PSObject.Properties.Name) {
                        if (!$Existing.repeated.$i -or $Existing.repeated.$i -ne $Exclusion.repeated.$i) {
                          # Check each sub-property under 'repeated'
                          'repeated'
                        }
                      }
                    } elseif (!$Existing.$_ -or $Exclusion.$_ -ne $Existing.$_) {
                      $_
                    }
                  } | Select-Object -Unique
                  if ($Modified) {
                    # Update identifiers and modify exclusion
                    @('id','policy_id').foreach{ $Exclusion.$_ = $Existing.$_ }
                    $Req = $Exclusion | Edit-FalconFileVantageExclusion
                    if ($Req) {
                      @($Modified).foreach{
                        if ($_ -eq 'repeated') {
                          # Convert 'repeated' to a string for CSV output
                          Add-Result Modified $Req FileVantageExclusion $_ ($Existing.$_ | Format-List |
                            Out-String).Trim() ($Req.$_ | Format-List | Out-String).Trim()
                        } else {
                          Add-Result Modified $Req FileVantageExclusion $_ $Existing.$_ $Req.$_
                        }
                      }
                    }
                  }
                } else {
                  # Create FileVantageExclusion
                  $Exclusion.policy_id = $Policy.id
                  $Req = $Exclusion | New-FalconFileVantageExclusion
                  if ($Req) { Add-Result Created $Req FileVantageExclusion }
                }
              }
            }
            # Assign rule_groups and host_groups
            @('rule_groups','host_groups').foreach{ if ($Policy.$_) { Submit-Group $Pair.Key $_ $Policy $Cid }}
            if ($Cid.enabled -ne $Policy.enabled) {
              # Enable/disable FileVantagePolicy
              $Req = $Policy | Edit-FalconFileVantagePolicy
              if ($Req) { Add-Result Modified $Req $Pair.Key enabled $Cid.enabled $Policy.enabled }
            }
          } else {
            # Assign IoaGroup and HostGroup
            if ($Policy.ioa_rule_groups) { Submit-Group $Pair.Key ioa_rule_groups $Policy $Cid }
            if ($Policy.groups) { Submit-Group $Pair.Key groups $Policy $Cid }
            if ($Policy.host_groups) { Submit-Group $Pair.Key host_groups $Policy $Cid }
            if ($Cid.enabled -ne $Policy.enabled) {
              # Enable/disable policy
              [string]$Action = if ($Policy.enabled -eq $true) { 'enable' } else { 'disable' }
              $Req = Invoke-PolicyAction $Pair.Key $Action $Policy.id
              if ($Req) { Add-Result Modified $Req $Pair.Key enabled $Cid.enabled $Policy.enabled }
            }
          }
        }
      }
      [void]$Pair.Value.Remove('Modify')
    }
  }
  end {
    $Config
    <#
    if ($Config.Result | Where-Object { $_.action -ne 'Ignored' }) {
      # Output warning for existing policy precedence
      foreach ($Item in ($Config.Result | Where-Object { $_.action -eq 'Created' -and $_.type -match 'Policy$' } |
      Select-Object type,platform -Unique)) {
        if ($Config.($Item.type).Cid | Where-Object { $_.platform_name -eq $Item.platform -and $_.name -ne
        'platform_default' }) {
          $PSCmdlet.WriteWarning("[Import-FalconConfig] Existing $($Item.platform) $(
            $Item.type) items were found. Verify precedence!")
        }
      }
    }
    if ($Config.Result) {
      # Output results to CSV
      @($Config.Result).foreach{ try { $_ | Export-Csv $OutputFile -NoTypeInformation -Append } catch { $_ }}
      if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
    }
    #>
  }
}