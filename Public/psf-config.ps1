function Export-FalconConfig {
<#
.SYNOPSIS
Create an archive containing Falcon configuration files
.DESCRIPTION
Uses various PSFalcon commands to gather and export groups, policies and exclusions as a collection
of Json files within a zip archive. The exported files can be used with 'Import-FalconConfig' to restore
configurations to your existing CID or create them in another CID.
.PARAMETER Select
Selected items to export from your current CID, or leave unspecified to export all available items
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Configuration-Import-Export
#>
    [CmdletBinding(DefaultParameterSetName='ExportItem',SupportsShouldProcess)]
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
            $ConfigFile = Join-Path $Location "$String.json"
            $Param = @{ Detailed = $true; All = $true}
            $Config = if ($String -match '^(DeviceControl|Firewall|Prevention|Response|SensorUpdate)Policy$') {
                # Create policy exports in 'platform_name' order to retain precedence
                @('Windows','Mac','Linux').foreach{
                    & "Get-Falcon$String" @Param -Filter "platform_name:'$_'" 2>$null
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
            if (!$Select) {
                # Use items in 'ValidateSet' when not provided
                [string[]]$Select = @((Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({ $_.Name -eq
                'ExportItem' }).Parameters.Where({ $_.Name -eq 'Select' }).Attributes.ValidValues).foreach{
                    $_
                }
            }
            if ($Select -match '^((Ioa|Ml|Sv)Exclusion|Ioc)$' -and $Select -notcontains 'HostGroup') {
                # Force 'HostGroup' when exporting Exclusions or IOCs
                [string[]]$Select = @($Select + 'HostGroup')
            }
            # Force 'FirewallRule' when exporting 'FirewallGroup'
            if ($Select -contains 'FirewallGroup') { [string[]]$Select = @($Select + 'FirewallRule') }
            [string[]]$JsonFiles = foreach ($String in $Select) {
                # Retrieve results, export to Json and capture file name
                ,(Get-ItemContent $String)
            }
            if ($JsonFiles -and $PSCmdlet.ShouldProcess($ExportFile,'Compress-Archive')) {
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
                        Write-Verbose "[Export-FalconConfig] Removing '$_'."
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
https://github.com/crowdstrike/psfalcon/wiki/Configuration-Import-Export
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
        [ValidateSet('DeviceControlPolicy','FirewallPolicy','PreventionPolicy','ResponsePolicy',
            'SensorUpdatePolicy')]
        [string[]]$ModifyDefault,
        [ValidateSet('DeviceControlPolicy','FirewallGroup','FirewallPolicy','HostGroup','IoaExclusion','IoaGroup',
            'Ioc','MlExclusion','PreventionPolicy','ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
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
                } else {
                    if ($Item.instance_id) { $Item.instance_id } else { $Item.id }
                }
                name = if ($Item.value) {
                    if ($Item.type) { $Item.type,$Item.value -join ':' } else { $Item.value }
                } else {
                    $Item.name
                }
                platform = if ($Item.platform) {
                    if ($Item.platform -is [string[]]) { $Item.platform -join ',' } else { $Item.platform }
                } elseif ($Item.platforms) {
                    $Item.platforms -join ','
                } elseif ($Item.platform_name) {
                    $Item.platform_name
                } else {
                    $null
                }
                action = $Action
                property = $Property
                old_value = $Old
                new_value = $New
                comment = $Comment
            }
            $Config.Result.Add($Obj)
            if ($Action -match '^(Created|Modified)$') {
                # Notify when items are created or modified
                [System.Collections.Generic.List[string]]$Notify = @('[Import-FalconConfig]',$Action)
                if ($Property) { $Notify.Add("'$Property' for") }
                if ($Obj.platform -and $Obj.platform -notmatch ',') { $Notify.Add($Obj.platform) }
                $Notify.Add($Type)
                $Notify.Add("'$($Obj.Name)'.")
                Write-Host ($Notify -join ' ')
            }
        }
        function Compare-ImportData ([string]$Item) {
            if ($Config.$Item.Cid) {
                # Define properties for comparison between imported and existing items
                [string[]]$Properties = ($Config.$Item.Cid | Get-Member -MemberType NoteProperty).Name
                [string[]]$Compare = @('name','type','value').foreach{ if ($Properties -contains $_) { $_ }}
                $FilterScript = [scriptblock]::Create((@($Compare).foreach{
                    "`$Config.$($Item).Cid.$($_) -notcontains `$_.$($_)" }) -join ' -and ')
                @($Config.$Item.Import | Where-Object -FilterScript $FilterScript).foreach{ $_ }
                if ($ModifyExisting -contains $Item) {
                    # Capture (non-policy) items to modify
                    $FilterScript = [scriptblock]::Create((@($Compare).foreach{
                        "`$Config.$($Item).Cid.$($_) -contains `$_.$($_)" }) -join ' -and ')
                    @($Config.$Item.Import | Where-Object -FilterScript $FilterScript).foreach{
                        $Config.$Item.Modify.Add($_)
                    }
                }
            } elseif ($Config.$Item.Import) {
                # Output all items
                @($Config.$Item.Import).foreach{ $_ }
            }
        }
        function Compare-Setting ([object]$New,[object]$Old,[string]$Type,[string]$Property,[switch]$Result) {
            if ($Type -match 'Policy$') {
                # Compare modified policy settings
                $NewArr = if ($New.prevention_settings) {
                    $New.prevention_settings
                } else {
                    $New.settings
                }
                $OldArr = if ($Old.prevention_settings) {
                    $Old.prevention_settings
                } else {
                    $Old.settings
                }
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
                                        Add-Result Modified $New $Type ($Item.id,$Name -join ':') (($OldArr |
                                            Where-Object { $_.id -eq $Item.id }).value.$Name) $Item.value.$Name
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
                        $OldValue = ($Old.$Property | Where-Object { $_.name -eq $Name }).values |
                            ConvertTo-Json -Compress
                        $NewValue = ($New.$Property | Where-Object { $_.name -eq $Name }).values |
                            ConvertTo-Json -Compress
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
                [object[]]$Object.prevention_settings = $Object.prevention_settings.settings |
                    Select-Object id,value
            }
            if ($Object.settings.settings) {
                [object[]]$Object.settings = $Object.settings.settings | Select-Object id,value
            }
            if ($Object.groups.id) { [string[]]$Object.groups = $Object.groups.id }
            if ($Object.rule_group.id) { [string[]]$Object.rule_group = $Object.rule_group.id }
            if ($Object.ioa_rule_groups.id) { [string[]]$Object.ioa_rule_groups = $Object.ioa_rule_groups.id }
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
                $Output[$Item] = @{
                    Import = ($Import | Select-Object -ExcludeProperty created_by,modified_by,
                        created_timestamp,modified_timestamp)
                    Modify = [System.Collections.Generic.List[object]]@()
                }
                $Output.Ids[$Item] = [System.Collections.Generic.List[object]]@()
                $Item
            }
            if ($FileStream) { $FileStream.Dispose() }
            if ($Msg) { Write-Host "[Import-FalconConfig] Imported from $($FilePath): $($Msg -join ', ')." }
            $Output
        }
        function Invoke-PolicyAction ([string]$Type,[string]$Action,[string]$PolicyId,[string]$GroupId) {
            try {
                # Perform an action on a policy and output result
                if ($GroupId) {
                    $PolicyId | & "Invoke-Falcon$($Type)Action" -Name $Action -GroupId $GroupId
                } else {
                    $PolicyId | & "Invoke-Falcon$($Type)Action" -Name $Action
                }
            } catch {
                Write-Error $_
            }
        }
        function Submit-Group ([string]$Policy,[string]$Property,[object]$Obj,[object]$Cid) {
            [string]$Invoke = if ($Property -eq 'ioa_rule_groups') { 'add-rule-group' } else { 'add-host-group' }
            [string]$Group = if ($Property -eq 'ioa_rule_groups') { 'IoaGroup' } else { 'HostGroup' }
            $Target = if ($Cid) { $Cid } else { $Obj }
            $Req = foreach ($Id in $Obj.$Property) {
                [object]$Match = $Config.Ids.$Group | Where-Object { $_.old_id -eq $Id }
                if ($Match -and $Target.$Property -notcontains $Match.new_id) {
                    @(Invoke-PolicyAction $Policy $Invoke $Target.id $Match.new_id).foreach{ $_ }
                }
            }
            if ($Req) {
                Add-Result Modified $Req[-1] $Policy $Property ($Target.$Property -join ',') (
                    $Req[-1].$Property.id -join ',')
            }
        }
        function Update-Id ([object]$Item,[string]$Type) {
            if ($Config.Ids.$Type) {
                # Add 'new_id' to 'Ids'
                [string[]]$Compare = @('platform_name','platform','type','value','name').foreach{
                    if ($Item.$_) { $_ }
                }
                [string]$Filter = (@($Compare).foreach{"`$_.$($_) -eq '$($Item.$_)'" }) -join ' -and '
                $FilterScript = [scriptblock]::Create($Filter)
                @($Config.Ids.$Type | Where-Object -FilterScript $FilterScript).foreach{
                    $_.new_id = if ($Item.family) { $Item.family } else { $Item.id }
                }
            }
        }
        # Convert 'Path' to absolute and set 'OutputFile'
        [string]$ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        [string]$OutputFile = Join-Path (Get-Location).Path "FalconConfig_$(Get-Date -Format FileDateTime).csv"
        [string]$UserAgent = (Show-FalconModule).UserAgent
    }
    process {
        # Import configuration files and capture id values for comparison
        $Config = Import-ConfigData $ArchivePath
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Value.Import })) {
            foreach ($Import in $Pair.Value.Import) {
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
            # Retrieve existing items from CID and update their id values
            $Pair.Value['Cid'] = try {
                Write-Host "[Import-FalconConfig] Retrieving '$($Pair.Key)'..."
                @(& "Get-Falcon$($Pair.Key)" -Detailed -All).foreach{
                    Update-Id $_ $Pair.Key
                    Compress-Property $_
                }
            } catch {
                throw $_
            }
            if ($Pair.Key -match 'Policy$') {
                $Pair.Value.Import = foreach ($Policy in $Pair.Value.Import) {
                    if (!($Config.($Pair.Key).Cid | Where-Object { $_.platform_name -eq $Policy.platform_name -and
                    $_.name -eq $Policy.name })) {
                        # Keep only missing policy items for each OS under 'Import'
                        $Policy
                        $Pair.Value.Modify.Add($Policy.PSObject.Copy())
                    } else {
                        # Add to relevant 'Modify' list or add result as 'Ignored'
                        if (($ModifyDefault -contains $Pair.Key -and $Policy.name -eq 'platform_default') -or
                        ($ModifyExisting -contains $Pair.Key -and $Policy.name -ne 'platform_default')) {
                            $Pair.Value.Modify.Add($Policy.PSObject.Copy())
                        } elseif ($Policy.name -ne 'platform_default') {
                            Add-Result Ignored $Policy $Pair.Key -Comment Exists
                        }
                    }
                }
            } elseif ($Pair.Key -ne 'FirewallRule') {
                foreach ($Item in $Pair.Value.Import) {
                    # Track 'Ignored' items for final output
                    [string]$Comment = if ($Item.deleted -eq $true) {
                        'Deleted'
                    } elseif ($Item.type -and $Item.value -and ($Pair.Value.Cid | Where-Object { $_.type -eq
                    $Item.type -and $_.value -eq $Item.value })) {
                        'Exists'
                    } elseif ($Item.value -and ($Pair.Value.Cid | Where-Object { $_.value -eq $Item.value })) {
                        'Exists'
                    } elseif ($Pair.Value.Cid | Where-Object { $_.name -eq $Item.name }) {
                        'Exists'
                    }
                    if ($Comment -and $ModifyExisting -notcontains $Pair.Key) {
                        Add-Result Ignored $Item $Pair.Key -Comment $Comment
                    }
                }
                # Remove items that will not be created from 'Import'
                $Pair.Value.Import = Compare-ImportData $Pair.Key
            }
            if ($Pair.Key -eq 'SensorUpdatePolicy' -and ($Pair.Value.Import -or $Pair.Value.Modify)) {
                # Retrieve available sensor build versions to update 'tags'
                [object[]]$Builds = try {
                    Write-Host "[Import-FalconConfig] Retrieving available sensor builds..."
                    Get-FalconBuild
                } catch {
                    throw "Failed to retrieve available sensor builds for '$(
                        $Pair.Key)' import. Verify 'Sensor Update Policies: Write' permission."
                }
                foreach ($Item in @($Pair.Value.Import + $Pair.Value.Modify)) {
                    # Update tagged builds with current tagged build versions
                    if ($Item.settings.build -match '^\d+\|') {
                        [string]$Tag = ($Item.settings.build -split '\|',2)[-1]
                        [string]$Current = ($Builds | Where-Object { $_.build -like "*|$Tag" -and $_.platform -eq
                            $Item.platform_name }).build
                        if ($Item.settings.build -ne $Current) { $Item.settings.build = $Current }
                    }
                    if ($Item.settings.variants) {
                        # Update tagged 'variant' builds with current tagged build versions
                        @($Item.settings.variants | Where-Object { $_.build }).foreach{
                            [string]$Tag = ($_.build -split '\|',2)[-1]
                            [string]$Current = ($Builds | Where-Object { $_.build -like "*|$Tag" -and
                                $_.platform -eq $Item.platform_name }).build
                            if ($_.build -ne $Current) { $_.build = $Current }
                        }
                    }
                }
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -eq 'HostGroup' -and $_.Value.Import })) {
            foreach ($HostGroup in ($Pair.Value.Import | & "New-Falcon$($Pair.Key)")) {
                # Create HostGroup
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
                            [string]$NewId = ($Config.Ids.HostGroup | Where-Object { $_.old_id -eq $OldId }).new_id
                            if ($NewId) { [string[]]$Item.$_ = $Item.$_ -replace $OldId,$NewId }
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
            if ($Pair.Key -eq 'Ioc') {
                @($Pair.Value.Import | & "New-Falcon$($Pair.Key)").foreach{
                    # Create Ioc
                    Update-Id $_ $Pair.Key
                    Add-Result Created $_ $Pair.Key
                }
            } elseif ($Pair.Key -eq 'FirewallGroup') {
                foreach ($Item in $Pair.Value.Import) {
                    [object]$FwGroup = $Item | Select-Object name,enabled,description,comment,rule_ids
                    if ($FwGroup) {
                        if ($FwGroup.rule_ids) {
                            # Select FirewallRule from import using 'family' as 'id' value
                            [object[]]$Rules = foreach ($Id in $FwGroup.rule_ids) {
                                $Config.FirewallRule.Import | Where-Object { $_.family -eq $Id -and
                                    $_.deleted -eq $false }
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
                                    if ($Req.enabled -eq $false -and $Rule.enabled -eq $true) {
                                        $Req.enabled = $true
                                    }
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
            [string[]]$Select = switch ($Pair.Key) {
                # Select required properties for comparison
                'FirewallGroup' { 'name','enabled','rule_ids' }
                'HostGroup' { 'group_type','name','assignment_rule' }
                'IoaGroup' { 'enabled','name','platform','rules' }
                'IoaExclusion' {
                    'name','pattern_id','pattern_name','cl_regex','ifn_regex','groups',
                        'applied_globally'
                }
                'Ioc' {
                    'applied_globally','action','deleted','expiration','host_groups','mobile_action',
                        'platforms','severity','tags','type','value'
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
                                if ($Pair.Key -eq 'IoaGroup' -and $_ -eq 'rules') {
                                    foreach ($Rule in $Item.$_) {
                                        # Evaluate each IoaRule
                                        [object]$CidRule = $Cid.$_ | Where-Object { $_.ruletype_id -eq
                                            $Rule.ruletype_id -and $_.name -eq $Rule.name -and $Rule.deleted -ne
                                            $true }
                                        [string[]]$RuleDiff = if ($CidRule) {
                                            @('enabled','pattern_severity','action_label').foreach{
                                                if (Compare-Object $Rule.$_ $CidRule.$_) { $_ }
                                            }
                                            foreach ($FieldValue in $Rule.field_values) {
                                                # Evaluate 'field_value' as a Json string for each IoaRule
                                                [object]$CidFieldValue = $CidRule.field_values | Where-Object {
                                                    $_.name -eq $FieldValue.name -and $_.type -eq
                                                    $FieldValue.type }
                                                if ($CidFieldValue) {
                                                    if (Compare-Object ($FieldValue.values | ConvertTo-Json) (
                                                    $CidFieldValue.values | ConvertTo-Json)) {
                                                        'field_values'
                                                    }
                                                }
                                            }
                                        }
                                        if ($RuleDiff) {
                                            # Copy existing rule and modify properties
                                            [object]$RuleEdit = $CidRule.PSObject.Copy()
                                            @($RuleDiff).foreach{ $RuleEdit.$_ = $Rule.$_ }
                                            @(Edit-FalconIoaRule -RuleUpdate $RuleEdit -RuleGroupId (
                                            $Item.id)).foreach{
                                                @($RuleDiff).foreach{
                                                    # Capture result for each updated setting against original
                                                    Compare-Setting $RuleEdit $CidRule IoaRule $_ -Result
                                                }
                                            }
                                        }
                                    }
                                } elseif ($Pair.Key -eq 'FirewallGroup' -and $_ -eq 'rule_ids') {
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
                                } else {
                                    Compare-Object $Item.$_ $Cid.$_
                                }
                            }
                            if ($Diff -or ($null -ne $Item.$_ -and $null -eq $Cid.$_)) {
                                # Output properties that differ, or are not present in CID
                                $Modify.Add($_)
                            }
                        }
                        # Output items with properties to be modified and remove from 'Modify' list
                        if ($Modify.Count -gt 1) { $Item | Select-Object $Modify }
                    }
                }
                if ($EditList) {
                    foreach ($Edit in $EditList) {
                        # Update with current 'id' and 'comment' when appropriate
                        Set-Property $Edit id ($Config.Ids.($Pair.Key) | Where-Object { $_.old_id -eq
                            $Edit.id }).new_id
                        if ($Pair.Key -ne 'HostGroup') {
                            Set-Property $Edit comment ($UserAgent,"Import-FalconConfig" -join ': ')
                        }
                    }
                    if ($Pair.Key -eq 'FirewallGroup') {
                        [hashtable[]]$DiffOp = @($EditList).foreach{
                            # Create 'DiffOperations' for FirewallGroup changes
                            if ($null -ne $_.enabled) {
                                @{ op = 'replace'; path = "/enabled"; value = $_.enabled }
                            }
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
                                @($Result.PSObject.Properties.Name).Where({ $_ -ne 'id' -and $_ -ne
                                'comment' }).foreach{
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
                [void]$Pair.Value.Remove('Modify')
            }
        }
        foreach ($Pair in $Config.GetEnumerator().Where({ $_.Key -match 'Policy$' -and $_.Value.Modify })) {
            foreach ($Policy in $Pair.Value.Modify) {
                # Update policy with current id value and use CID value for comparison
                [string]$Policy.id = ($Config.Ids.($Pair.Key) | Where-Object { $_.name -eq $Policy.name -and
                    $_.platform_name -eq $Policy.platform_name }).new_id
                [object]$Cid = $Config.($Pair.Key).Cid | Where-Object { $_.id -eq $Policy.id }
                if ($Pair.Key -eq 'FirewallPolicy') {
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
                } elseif ($Policy.prevention_settings -or $Policy.settings) {
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
                if ($Policy.ioa_rule_groups) {
                    # Assign IoaGroup
                    Submit-Group $Pair.Key ioa_rule_groups $Policy $Cid
                }
                if ($Policy.name -ne 'platform_default' -and $Policy.groups) {
                    # Assign HostGroup
                    Submit-Group $Pair.Key groups $Policy $Cid
                }
                if ($Policy.name -ne 'platform_default' -and $Cid.enabled -ne $Policy.enabled) {
                    # Enable/disable non-default policies
                    [string]$Action = if ($Policy.enabled -eq $true) { 'enable' } else { 'disable' }
                    $Req = Invoke-PolicyAction $Pair.Key $Action $Policy.id
                    if ($Req) {
                        Add-Result Modified $Req $Pair.Key enabled $Cid.enabled $Policy.enabled
                    }
                }
            }
            [void]$Pair.Value.Remove('Modify')
        }
    }
    end {
        if ($Config.Result | Where-Object { $_.action -ne 'Ignored' }) {
            # Output warning for existing policy precedence
            foreach ($Item in ($Config.Result | Where-Object { $_.action -eq 'Created' -and $_.type -match
            'Policy$' } | Select-Object type,platform)) {
                if ($Config.($Item.type).Cid | Where-Object { $_.platform_name -eq $Item.platform -and $_.name -ne
                'platform_default' }) {
                    Write-Warning "Existing $($Item.platform) $($Item.type) items were found. Verify precedence!"
                }
            }
        }
        @($Config.Result).foreach{ try { $_ | Export-Csv $OutputFile -NoTypeInformation -Append } catch { $_ }}
        if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
    }
}