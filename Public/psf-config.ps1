function Export-FalconConfig {
<#
.SYNOPSIS
Create an archive containing Falcon configuration files
.DESCRIPTION
Uses various PSFalcon commands to gather and export groups, policies and exclusions as a collection
of Json files within a zip archive. The exported files can be used with 'Import-FalconConfig' to restore
configurations to your existing CID or create them in another CID.
.PARAMETER Select
Selected items to export from your current CID, or leave blank to export all available items
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Configuration-Import-Export
#>
    [CmdletBinding(DefaultParameterSetName='ExportItem')]
    param(
        [Parameter(ParameterSetName='ExportItem',Position=1)]
        [ValidateSet('HostGroup','IoaGroup','FirewallGroup','DeviceControlPolicy','FirewallPolicy',
            'PreventionPolicy','ResponsePolicy','SensorUpdatePolicy','Ioc','IoaExclusion','MlExclusion',
            'Script','SvExclusion')]
        [Alias('Items')]
        [string[]]$Select,
        [Parameter(ParameterSetName='ExportItem')]
        [switch]$Force
    )
    begin {
        function Get-ItemContent ([string]$String) {
            # Request content for provided 'Item'
            Write-Host "[Export-FalconConfig] Exporting '$String'..."
            $ConfigFile = Join-Path -Path $Location -ChildPath "$String.json"
            $Param = @{ Detailed = $true; All = $true}
            $Config = if ($String -match '^(DeviceControl|Firewall|Prevention|Response|SensorUpdate)Policy$') {
                # Create policy exports in 'platform_name' order to retain precedence
                @('Windows','Mac','Linux').foreach{
                    & "Get-Falcon$String" @Param -Filter "platform_name:'$_'+name:!'platform_default'" 2>$null
                }
            } else {
                & "Get-Falcon$String" @Param 2>$null
            }
            if ($Config -and $String -eq 'FirewallPolicy') {
                # Export firewall settings
                Write-Host "[Export-FalconConfig] Exporting 'FirewallSetting'..."
                $Settings = Get-FalconFirewallSetting -Id $Config.id 2>$null
                foreach ($Result in $Settings) {
                    ($Config | Where-Object { $_.id -eq $Result.policy_id }).PSObject.Properties.Add(
                        (New-Object PSNoteProperty('settings',$Result)))
                }
            }
            if ($Config) {
                # Export results to json file and output created file name
                ConvertTo-Json @($Config) -Depth 32 | Out-File $ConfigFile -Append
                $ConfigFile
            }
        }
        # Get current location
        $Location = (Get-Location).Path
        
        # Set output archive path
        $ExportFile = Join-Path $Location "FalconConfig_$(Get-Date -Format FileDateTime).zip"
    }
    process {
        $OutPath = Test-OutFile $ExportFile
        if ($OutPath.Category -eq 'WriteError' -and !$Force) {
            Write-Error @OutPath
        } else {
            if (!$PSBoundParameters.Select) {
                # Use items in 'ValidateSet' when not provided
                $PSBoundParameters.Select = @((Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({
                    $_.Name -eq 'ExportItem' }).Parameters.Where({ $_.Name -eq
                    'Select' }).Attributes.ValidValues).foreach{ $_ }
            }
            if ($PSBoundParameters.Select -match '^((Ioa|Ml|Sv)Exclusion|Ioc)$' -and
            $PSBoundParameters.Select -notcontains 'HostGroup') {
                # Force 'HostGroup' when exporting Exclusions or IOCs
                $PSBoundParameters.Select += ,'HostGroup'
            }
            if ($PSBoundParameters.Select -contains 'FirewallGroup') {
                # Force 'FirewallRule' when exporting 'FirewallGroup'
                $PSBoundParameters.Select += ,'FirewallRule'
            }
            # Retrieve results, export to Json and capture file name
            $JsonFiles = foreach ($String in $PSBoundParameters.Select) { ,(Get-ItemContent $String) }
            if ($JsonFiles) {
                # Archive Json exports with content and remove them when complete
                $Param = @{
                    Path = (Get-ChildItem | Where-Object { $JsonFiles -contains $_.FullName -and
                        $_.Length -gt 0 }).FullName
                    DestinationPath = $ExportFile
                    Force = $Force
                }
                Compress-Archive @Param
                @($JsonFiles).foreach{
                    if (Test-Path $_) {
                        Write-Verbose "Deleting '$_'."
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
Import configurations from a 'FalconConfig' archive into your Falcon environment
.DESCRIPTION
Creates groups,policies,exclusions and rules within a 'FalconConfig' archive within your authenticated
Falcon environment.

Anything that already exists will be ignored and no existing items will be modified.

The '-Force' parameter forces the script to assign exceptions,policies and rules to existing host groups
with the same names as the ones provided in the configuration file.
.PARAMETER Path
'FalconConfig' archive path
.PARAMETER Force
Assign imported items to existing host groups
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Configuration-Import-Export
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [ValidatePattern('\.zip$')]
        [ValidateScript({
            if (Test-Path $_) { $true } else { throw "Cannot find path '$_' because it does not exist." }
        })]
        [string]$Path,
        [switch]$Force
    )
    begin {
        function Add-ListId ([object]$Item,[string]$Type,[string]$Reason) {
            $Obj = if ($Reason) {
                [PSCustomObject]@{ id = $Item.id; reason = $Reason }
            } else {
                [PSCustomObject]@{ old_id = $Item.id; new_id = $null }
            }
            @('platform_name','platforms','platform','type','value','name').foreach{
                if ($Item.$_) { Add-Property $Obj $_ $Item.$_ }
            }
            if ($Obj.reason) {
                # Add excluded item to list for final output
                [void]$Config.Excluded.$Type.Add($Obj)
            } else {
                # Capture item 'id' for assignment
                [void]$Config.Ids.$Type.Add($Obj)
            }
        }
        function Compare-ImportData ([string]$Item) {
            if ($Config.$Item.Cid) {
                # Define properties for comparison between imported and existing items
                [string[]]$Properties = ($Config.$Item.Cid | Get-Member -MemberType NoteProperty).Name
                [string[]]$Compare = @('name','type','value').foreach{ if ($Properties -contains $_) { $_ }}
                $FilterScript = [scriptblock]::Create((@($Compare).foreach{
                    "`$Config.$($Item).Cid.$($_) -notcontains `$_.$($_)" }) -join ' -and ')
                Get-ConfigItem $Item Import $FilterScript
            } elseif ($Config.$Item.Import) {
                # Output all items
                @($Config.$Item.Import).foreach{
                    Write-Verbose "[Compare-ImportData] $($Item).Import: $($_.id)"
                    $_
                }
            }
        }
        function Get-CidValue ([string]$Item) {
            try {
                # Retrieve existing configurations from CID, excluding 'platform_default'
                Write-Host "[Import-FalconConfig] Retrieving '$Item'..."
                $Param = @{ Detailed = $true; All = $true }
                if ($Item -match 'Policy$') { $Param['Filter'] = "name:!'platform_default'" }
                & "Get-Falcon$($Item)" @Param
            } catch {
                throw $_
            }
        }
        function Get-ConfigItem ([string]$Item,[string]$Type,[scriptblock]$FilterScript) {
            @($Config.$Item.$Type | Where-Object -FilterScript $FilterScript).foreach{
                Write-Verbose "[Get-ConfigItem] $($Item).$($Type): $($_.id)"
                $_
            }
        }
        function Import-ConfigData ($FilePath) {
            # Load 'FalconConfig' archive into memory
            $Output = @{ Excluded = @{}; Ids = @{}}
            $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                Get-Content -Path $FilePath -AsByteStream
            } else {
                Get-Content -Path $FilePath -Encoding Byte -Raw
            }
            [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
            $FileStream = New-Object System.IO.MemoryStream
            $FileStream.Write($ByteStream,0,$ByteStream.Length)
            $ConfigArchive = New-Object System.IO.Compression.ZipArchive($FileStream)
            [string[]]$Msg = foreach ($FullName in $ConfigArchive.Entries.FullName) {
                # Import Json, filter to required properties, add to output, then output name for notification
                $Filename = $ConfigArchive.GetEntry($FullName)
                $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
                $Import = ConvertFrom-Json -InputObject ((New-Object System.IO.StreamReader(
                    $Filename.Open())).ReadToEnd())
                $Import = $Import | Select-Object $ConfigFields.$Item.Import
                $Output[$Item] = @{ Import = $Import }
                @('Excluded','Ids').foreach{ $Output.$_[$Item] = [System.Collections.ArrayList]@() }
                $Item
            }
            if ($FileStream) { $FileStream.Dispose() }
            if ($Msg) { Write-Host "[Import-FalconConfig] Imported from $($FilePath): $($Msg -join ', ')." }
            $Output
        }
        function New-ResultObject ([object]$Item,[string]$Type) {
            if ($Item -and $Type) {
                # Create object for CSV output
                [PSCustomObject]@{
                    status = if ($Item.reason) { 'Excluded' } else { 'Created' }
                    type = $Type
                    id = if ($Item.reason -eq 'Excluded') {
                        # Exclude 'id' when item has been excluded
                        $null
                    } elseif ($Item.instance_id) {
                        $Item.instance_id
                    } else {
                        $Item.id
                    }
                    platform = if ($Item.platform_name) {
                        $Item.platform_name
                    } elseif ($Item.platforms) {
                        $Item.platforms -join ','
                    } elseif ($Item.platform) {
                        if ($Item.platform -is [array]) { $Item.platform -join ',' } else { $Item.platform }
                    } else {
                        $null
                    }
                    name = if ($Item.type -and $Item.value) {
                        "$($Item.type):$($Item.value)"
                    } elseif ($Item.value) {
                        $Item.value
                    } else {
                        $Item.name
                    }
                    reason = if ($Item.reason) { $Item.reason } else { $null }
                }
            }
        }
        function Update-ListId ([object]$Item,[string]$Type) {
            if ($Config.Ids.$Type) {
                # Update 'Ids' with 'new_id'
                [string[]]$Compare = @('platform_name','platform','type','value','name').foreach{
                    if ($Item.$_) { $_ }
                }
                [string]$Filter = (@($Compare).foreach{"`$_.$($_) -eq '$($Item.$_)'" }) -join ' -and '
                $FilterScript = [scriptblock]::Create($Filter)
                $Config.Ids.$Type | Where-Object -FilterScript $FilterScript | ForEach-Object {
                    $_.new_id = $Item.id
                }
            }
        }
        # Convert 'Path' to absolute and set 'OutputFile'
        $ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $ForceEnabled = if ($PSBoundParameters.Force) { $true } else { $false }
        $OutputFile = Join-Path (Get-Location).Path "FalconConfig_$(Get-Date -Format FileDateTime).csv"
    }
    process {
        # Create 'ConfigData', import configuration files and create object to contain 'id' values for comparison
        $Config = Import-ConfigData -FilePath $ArchivePath
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Value.Import })) {
            foreach ($i in $Pair.Value.Import) {
                # Capture relevant assignment detail for imported items
                Add-ListId $i $Pair.Key
                if ($Pair.Key -match '^(Ml|Sv)Exclusion$' -and $i.applied_globally -eq $true) {
                    # Set 'groups' to 'all' for global exclusion
                    [string[]]$i.groups = 'all'
                }
                if ($i.groups.id) {
                    # Filter 'groups' to 'id' values
                    [string[]]$i.groups = $i.groups.id
                }
                if ($i.rule_group.id) {
                    # Filter 'rule_group' to 'id' values
                    [string[]]$i.rule_group = $i.rule_group.id
                }
                if ($i.ioa_rule_groups.id) {
                    # Filter 'ioa_rule_groups' to 'id' values
                    [string[]]$i.ioa_rule_groups = $i.ioa_rule_groups.id
                }
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -notmatch '^(Ids|Excluded)$' })) {
            # Retrieve existing items from CID
            $Pair.Value['Cid'] = [object[]](Get-CidValue $Pair.Key)
            if ($Pair.Value.Cid -and $ForceEnabled -eq $true) {
                # Add existing item 'ids' for assignment when '-Force' is enabled
                foreach ($i in $Pair.Value.Cid) { Update-ListId $i $Pair.Key }
            }
            if ($Pair.Key -match 'Policy$') {
                $Pair.Value.Import = foreach ($i in $Pair.Value.Import) {
                    # Keep only non-existing policy items for each OS under 'Import'
                    if (!($Config.($Pair.Key).Cid.Where({ $_.platform_name -eq $i.platform_name -and
                        $_.name -eq $i.name }))) { $i } else { Add-ListId $i $Pair.Key Exists }
                }
            } else {
                if ($Pair.Key -ne 'FirewallRule') {
                    # Track excluded items for final output, excluding 'FirewallRule' which can be duplicated
                    foreach ($i in $Pair.Value.Import) {
                        [string]$Reason = if ($i.deleted -and $i.deleted -eq $true) {
                            'Deleted'
                        } elseif ($i.type -and $i.value -and $Pair.Value.Cid.Where({ $_.type -eq $i.type -and
                        $_.value -eq $i.value })) {
                            'Exists'
                        } elseif ($i.value -and $Pair.Value.Cid.Where({ $_.value -eq $i.value })) {
                            'Exists'
                        } elseif ($Pair.Value.Cid.Where({ $_.name -eq $i.name })) {
                            'Exists'
                        }
                        if ($Reason) { Add-ListId $i $Pair.Key $Reason }
                    }
                    # Remove excluded items from 'Import'
                    $Pair.Value.Import = Compare-ImportData $Pair.Key
                }
            }
            if ($Pair.Key -eq 'SensorUpdatePolicy' -and $Pair.Value.Import) {
                # Retrieve available sensor build versions to update 'tags'
                $Builds = try {
                    Write-Host "[Import-FalconConfig] Retrieving available sensor builds..."
                    Get-FalconBuild
                } catch {
                    throw "Failed to retrieve available sensor builds for '$(
                        $Pair.Key)' import. Verify 'Sensor Update Policies: Write' permission."
                }
                foreach ($i in $Pair.Value.Import) {
                    # Update tagged builds with current tagged build versions
                    if ($i.settings.build -match '^\d+\|') {
                        $Tag = ($i.settings.build -split '\|',2)[-1]
                        $Current = ($Builds | Where-Object { $_.build -like "*|$Tag" -and $_.platform -eq
                            $i.platform_name }).build
                        if ($i.settings.build -ne $Current) { $i.settings.build = $Current }
                    }
                    if ($i.settings.variants) {
                        # Update tagged 'variant' builds with current tagged build versions
                        @($i.settings.variants | Where-Object { $_.build }).foreach{
                            $Tag = ($_.build -split '\|',2)[-1]
                            $Current = ($Builds | Where-Object { $_.build -like "*|$Tag" -and $_.platform -eq
                                $i.platform_name }).build
                            if ($_.build -ne $Current) { $_.build = $Current }
                        }
                    }
                }
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -eq 'HostGroup' -and $_.Value.Import })) {
            # Create host groups
            ($Pair.Value)['Created'] = $Pair.Value.Import | & "New-Falcon$($Pair.Key)"
            foreach ($Group in $Pair.Value.Created) {
                # Notify and capture new 'id' values
                Write-Host "[Import-FalconConfig] Created $($Pair.Key) '$($Group.name)'."
                Update-ListId $Group $Pair.Key
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -notmatch '^(HostGroup|FirewallRule)$' -and
        $_.Value.Import })) {
            @($Pair.Value.Import).foreach{
                if ($_.groups -or $_.host_groups) {
                    # Update host group 'id' values
                    foreach ($OldId in $Config.Ids.HostGroup.old_id) {
                        $NewId = ($Config.Ids.HostGroup | Where-Object { $_.old_id -eq $OldId }).new_id
                        if ($NewId -and $_.groups) {
                            [string[]]$_.groups = $_.groups -replace $OldId,$NewId
                        } elseif ($NewId -and $_.host_groups) {
                            [string[]]$_.host_groups = $_.host_groups -replace $OldId,$NewId
                        }
                    }
                }
            }
            $Pair.Value['Created'] = if ($Pair.Key -eq 'FirewallGroup') {
                foreach ($i in $Pair.Value.Import) {
                    # Create FirewallGroup using properties from 'Import'
                    $FwGroup = $i | Select-Object name,enabled,description,comment,rule_ids
                    if ($FwGroup.rule_ids) {
                        # Select rule from Import using 'family' as 'id' value
                        [object[]]$Rules = foreach ($i in $FwGroup.rule_ids) {
                            $Config.FirewallRule.Import | Where-Object { $_.family -eq $i -and
                                $_.deleted -eq $false }
                        }
                        # Trim rule names to 64 characters
                        @($Rules).foreach{ if ($_.name.length -gt 64) { $_.name = ($_.name).SubString(0,63) }}
                        if ($Rules) {
                            # Add 'rules' and remove 'rule_ids' from object
                            Add-Property $FwGroup rules $Rules
                            $FwGroup.PSObject.Properties.Remove('rule_ids')
                        }
                    }
                    @($FwGroup | & "New-Falcon$($Pair.Key)").foreach{
                        # Append new 'id' to object, capture new 'id' and return result
                        Add-Property $FwGroup id $_
                        $FwGroup
                    }
                }
            } elseif ($Pair.Key -eq 'IoaGroup') {
                foreach ($i in $Pair.Value.Import) {
                    # Create IoaGroup
                    $IoaGroup = $i | & "New-Falcon$($Pair.Key)"
                    if ($IoaGroup) {
                        if ($i.rules) {
                            # Create IoaRules
                            $IoaGroup.rules = @($i.rules).foreach{
                                $_.rulegroup_id = $IoaGroup.id
                                $IoaRule = $_ | New-FalconIoaRule
                                if ($IoaRule.enabled -eq $false -and $_.enabled -eq $true) {
                                    # Enable created rule using status from 'Import'
                                    $IoaRule.enabled = $true
                                }
                                $IoaRule
                            }
                            if ($IoaGroup.rules.enabled -eq $true) {
                                @($IoaGroup | Edit-FalconIoaRule).foreach{
                                    @($_.rules).Where({ $_.enabled -eq $true }).foreach{
                                        # Notify of enabled rules
                                        Write-Host "[Import-FalconConfig] Enabled IoaRule '$($_.name)'."
                                    }
                                }
                            }
                        }
                        if ($i.enabled -eq $true -and $IoaGroup.enabled -eq $false) {
                            $IoaGroup.enabled = $true
                            $IoaGroup = @($IoaGroup | & "Edit-Falcon$($Pair.Key)").foreach{
                                # Enable IoaGroup and return result
                                Write-Host "[Import-FalconConfig] Enabled $($Pair.Key) '$($_.name)'."
                                $_
                            }
                        }
                        $IoaGroup
                    }
                }
            } elseif ($Pair.Key -eq 'Script') {
                foreach ($i in $Pair.Value.Import) {
                    # Create scripts
                    $Script = $i | & "Send-Falcon$($Pair.Key)"
                    if ($Script) { $i | Select-Object name,platform }
                }
            } else {
                # Create policies and exclusions
                $Pair.Value.Import | & "New-Falcon$($Pair.Key)"
            }
            foreach ($i in $Pair.Value.Created) {
                # Output notification of created item(s)
                $Name = if ($i.type -and $i.value) {
                    @($i.type,$i.value) -join ':'
                } elseif ($i.value) {
                    $i.value
                } else {
                    $i.name
                }
                if ($i.platform_name -or $i.platform) {
                    @('platform','platform_name').foreach{
                        if ($i.$_) {
                            Write-Host "[Import-FalconConfig] Created $($i.$_) $($Pair.Key) '$Name'."
                        }
                    }
                } else {
                    Write-Host "[Import-FalconConfig] Created $($Pair.Key) '$Name'."
                }
                # Capture new 'id' for assignment
                Update-ListId $i $Pair.Key
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -match 'Policy$' -and $_.Value.Created })) {
            foreach ($Policy in $Pair.Value.Created) {
                # Copy 'old' policy for replicating settings and assignment
                $Clone = $Config.($Pair.Key).Import | Where-Object { $_.name -eq $Policy.name -and
                    $_.platform_name -eq $Policy.platform_name }
                $Clone.id = $Policy.id
                if ($Pair.Key -eq 'FirewallPolicy') {
                    if ($Clone.settings.policy_id) {
                        # Add new policy 'id' to FirewallPolicy settings
                        $Clone.settings.policy_id = $Policy.id
                    }
                    foreach ($OldId in $Config.Ids.FirewallGroup.old_id) {
                        # Update 'rule_group_ids' with new 'id' values
                        $NewId = ($Config.Ids.FirewallGroup | Where-Object { $_.old_id -eq $OldId }).new_id
                        if ($NewId -and $Clone.rule_group_ids) {
                            [string[]]$_.rule_group_ids = $_.rule_group_ids -replace $OldId,$NewId
                        }
                    }
                    if ($Clone.settings) {
                        # Apply FirewallPolicy settings
                        $Settings = $Clone.settings | Edit-FalconFirewallSetting
                        if ($Settings) {
                            Add-Property $Policy settings $Clone.settings
                            Write-Host "[Import-FalconConfig] Applied settings to $($Policy.platform_name) $(
                                $Pair.Key) '$($Policy.name)'."
                        }
                    }
                } elseif ($Clone.settings -or $Clone.prevention_settings) {
                    # Apply settings
                    $Policy = $Clone | & "Edit-Falcon$($Pair.Key)"
                    if ($Policy) {
                        Write-Host "[Import-FalconConfig] Applied settings to $($Policy.platform_name) $(
                            $Pair.Key) '$($Policy.name)'."
                    }
                }
                if ($Pair.Key -eq 'PreventionPolicy' -and $Clone.ioa_rule_groups) {
                    # Assign IoaGroup to PreventionPolicy
                    foreach ($OldId in $Config.Ids.IoaGroup.old_id) {
                        $NewId = ($Config.Ids.IoaGroup | Where-Object { $_.old_id -eq $OldId }).new_id
                        if ($NewId) {
                            $Name = ($Config.Ids.IoaGroup | Where-Object { $_.old_id -eq $OldId }).name
                            $Policy = $Clone.id | & "Invoke-Falcon$($Pair.Key)Action" 'add-rule-group' $NewId
                            if ($Policy) {
                                Write-Host "[Import-FalconConfig] Assigned IoaGroup '$Name' to $(
                                    $Policy.platform_name) $($Pair.Key) '$($Policy.name)'."
                            }
                        }
                    }
                }
                foreach ($NewId in $Clone.groups) {
                    # Assign HostGroup to policy
                    $Name = ($Config.Ids.HostGroup | Where-Object { $_.new_id -eq $NewId }).name
                    if ($Name) {
                        $Policy = $Clone.id | & "Invoke-Falcon$($Pair.Key)Action" 'add-host-group' $NewId
                        if ($Policy) {
                            Write-Host "[Import-FalconConfig] Assigned HostGroup '$Name' to $(
                                $Policy.platform_name) $($Pair.Key) '$($Policy.name)'."
                        }
                    }
                }
                if ($Clone.enabled -eq $true) {
                    # Enable policy
                    $Policy = $Clone.id | & "Invoke-Falcon$($Pair.Key)Action" enable
                    if ($Policy) {
                        Write-Host "[Import-FalconConfig] Enabled $($Policy.platform_name) $($Pair.Key) '$(
                            $Policy.name)'."
                    }
                }
            }
        }
    }
    end {
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Value.Created })) {
            foreach ($i in $Pair.Value.Created) {
                # Output created items to CSV
                New-ResultObject $i $Pair.Key | Export-Csv $OutputFile -NoTypeInformation -Append
            }
        }
        foreach ($Pair in $Config.Excluded.GetEnumerator().Where({ $_.Value })) {
            foreach ($i in $Pair.Value) {
                # Output excluded items to CSV
                New-ResultObject $i $Pair.Key | Export-Csv $OutputFile -NoTypeInformation -Append
            }
        }
        if ($Config.Values.Created) {
            foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -match 'Policy$' -and $_.Value.Cid -and
            $_.Value.Created })) {
                foreach ($i in $Pair.Value.Created.platform_name) {
                    if ($Pair.Value.Cid | Where-Object { $_.platform_name -eq $i }) {
                        # Output precedence warning (per platform) if existing policies were found in CID
                        Write-Warning "Existing $i $($Pair.Key) items were found. Verify policy precedence!"
                    }
                }
            }
        }
        $Config
        #if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
    }
}