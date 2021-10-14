function Export-FalconConfig {
    [CmdletBinding(DefaultParameterSetName = 'ExportItems')]
    param(
        [Parameter(ParameterSetName = 'ExportItems', Position = 1)]
        [ValidateSet('HostGroup', 'IoaGroup', 'FirewallGroup', 'DeviceControlPolicy', 'FirewallPolicy',
            'PreventionPolicy', 'ResponsePolicy', 'SensorUpdatePolicy', 'Ioc', 'IoaExclusion', 'MlExclusion',
            'SvExclusion')]
        [array] $Items
    )
    begin {
        function Get-ItemContent ($Item) {
            # Request content for provided 'Item'
            Write-Host "Exporting '$Item'..."
            $ItemFile = Join-Path -Path $Location -ChildPath "$Item.json"
            $Param = @{
                Detailed = $true
                All = $true
            }
            $FileContent = if ($Item -match '^(DeviceControl|Firewall|Prevention|Response|SensorUpdate)Policy$') {
                # Create policy exports in 'platform_name' order to retain precedence
                @('Windows','Mac','Linux').foreach{
                    & "Get-Falcon$($Item)" @Param -Filter "platform_name:'$_'+name:!'platform_default'" 2>$null
                }
            } else {
                & "Get-Falcon$($Item)" @Param 2>$null
            }
            if ($FileContent -and $Item -eq 'FirewallPolicy') {
                # Export firewall settings
                Write-Host "Exporting 'FirewallSetting'..."
                $Settings = Get-FalconFirewallSetting -Ids $FileContent.id 2>$null
                foreach ($Result in $Settings) {
                    ($FileContent | Where-Object { $_.id -eq $Result.policy_id }).PSObject.Properties.Add(
                        (New-Object PSNoteProperty('settings', $Result)))
                }
            }
            if ($FileContent) {
                # Export results to json file and output created file name
                ConvertTo-Json -InputObject @( $FileContent ) -Depth 32 | Out-File -FilePath $ItemFile -Append
                $ItemFile
            }
        }
        # Get current location
        $Location = (Get-Location).Path
        $Export = if ($PSBoundParameters.Items) {
            # Use specified items
            $PSBoundParameters.Items
        } else {
            # Use items in 'ValidateSet' when not provided
            (Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({ $_.Name -eq
            'ExportItems' }).Parameters.Where({ $_.Name -eq 'Items' }).Attributes.ValidValues
        }
        # Set output archive path
        $ArchiveFile = Join-Path $Location -ChildPath "FalconConfig_$(Get-Date -Format FileDate).zip"
    }
    process {
        if (Test-Path $ArchiveFile) {
            throw "An item with the specified name $ArchiveFile already exists."
        }
        [array] $Export += switch ($Export) {
            { $_ -match '^((Ioa|Ml|Sv)Exclusion|Ioc)$' -and $Export -notcontains 'HostGroup' } {
                # Force 'HostGroup' when exporting Exclusions or IOCs
                'HostGroup'
            }
            { $_ -contains 'FirewallGroup' } {
                # Force 'FirewallRule' when exporting 'FirewallGroup'
                'FirewallRule'
            }
        }
        $JsonFiles = foreach ($Item in $Export) {
            # Retrieve results, export to Json and capture file name
            ,(Get-ItemContent -Item $Item)
        }
        if ($JsonFiles) {
            # Archive Json exports with content
            $Param = @{
                Path = (Get-ChildItem | Where-Object { $JsonFiles -contains $_.FullName -and
                    $_.Length -gt 0 }).FullName
                DestinationPath = $ArchiveFile
            }
            Compress-Archive @Param
            if (Test-Path $ArchiveFile) {
                # Display created archive
                Get-ChildItem $ArchiveFile
            }
            if (Test-Path $JsonFiles) {
                # Remove Json files when archived
                Remove-Item -Path $JsonFiles -Force
            }
        }
    }
}
function Import-FalconConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidatePattern('\.zip$')]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(Position = 2)]
        [switch] $Force
    )
    begin {
        # List of fields to capture/exclude/compare/export during import process
        $ConfigFields = @{
            DeviceControlPolicy = @{
                Import = @('id', 'platform_name', 'name', 'description', 'settings', 'enabled', 'groups')
            }
            FirewallGroup = @{
                Import = @('id', 'name', 'enabled', 'rule_ids', 'description')
            }
            FirewallPolicy = @{
                Import = @('id', 'name', 'platform_name', 'description', 'enabled', 'groups', 'settings')
            }
            FirewallRule = @{
                Import = @('id', 'family', 'name', 'description', 'enabled', 'platform_ids', 'direction',
                    'action', 'address_family', 'local_address', 'remote_address', 'protocol', 'local_port',
                    'remote_port', 'icmp', 'monitor', 'fields', 'rule_group')
            }
            FirewallSetting = @{
                Import = @('policy_id', 'platform_id', 'default_inbound', 'default_outbound', 'enforce',
                    'test_mode', 'rule_group_ids', 'is_default_policy')
            }
            HostGroup = @{
                Import = @('id', 'name', 'description', 'group_type', 'assignment_rule')
            }
            IoaExclusion = @{
                Import = @('id', 'cl_regex', 'ifn_regex', 'name', 'pattern_id', 'pattern_name', 'groups',
                    'comment', 'description', 'applied_globally')
            }
            IoaGroup = @{
                Import = @('id', 'platform', 'name', 'description', 'rules', 'enabled', 'version')
                Compare = @('platform', 'name')
            }
            IoaRule = @{
                Create = @('name', 'pattern_severity', 'ruletype_id', 'disposition_id', 'field_values',
                    'description', 'comment', 'enabled')
                Export = @('instance_id', 'name')
            }
            Ioc = @{
                Import = @('id', 'type', 'value', 'action', 'platforms', 'source', 'severity', 'description',
                    'tags', 'applied_globally', 'host_groups', 'expiration')
                Compare = @('type', 'value')
            }
            MlExclusion = @{
                Import = @('id', 'value', 'excluded_from', 'groups', 'applied_globally')
                Compare = @('value')
            }
            PreventionPolicy = @{
                Import = @('id', 'platform_name', 'name', 'description', 'prevention_settings',
                    'enabled', 'groups', 'ioa_rule_groups')
            }
            ResponsePolicy = @{
                Import = @('id', 'platform_name', 'name', 'description', 'settings', 'enabled', 'groups')
            }
            SensorUpdatePolicy = @{
                Import = @('id', 'platform_name', 'name', 'settings', 'enabled', 'description',
                    'groups')
            }
            SvExclusion = @{
                Import = @('id', 'value', 'groups', 'applied_globally')
                Compare = @('value')
            }
        }
        function Compare-ImportData ($Item) {
            if ($ConfigData.$Item.Cid) {
                $CompareFields = if ($ConfigFields.$Item.Compare) {
                    # Use defined fields for comparison with CID
                    $ConfigFields.$Item.Compare
                } elseif ($Item -match 'Policy$') {
                    # Use 'platform_name' and 'name' for policies
                    @('platform_name', 'name')
                } else {
                    # Use 'name'
                    @('name')
                }
                $FilterText = (($CompareFields).foreach{
                    "`$ConfigData.$($Item).Cid.$($_) -notcontains `$_.$($_)"
                }) -join ' -and '
                $Param = @{
                    Item         = $Item
                    Type         = 'Import'
                    FilterScript = [scriptblock]::Create($FilterText)
                }
                Get-ConfigItem @Param
            } elseif ($ConfigData.$Item.Import) {
                # Output all items
                @($ConfigData.$Item.Import).foreach{
                    Write-Verbose "[Compare-ImportData] $($Item).Import: $($_.id)"
                    $_
                }
            }
        }
        function Compress-Object ($Object) {
            foreach ($Item in $Object) {
                if ($Item.groups) {
                    # Keep 'id' and 'name' from 'groups'
                    $Item.groups = $Item.groups | Select-Object id, name
                }
                if ($Item.prevention_settings.settings) {
                    # Keep 'id' and 'value' from 'prevention_settings'
                    $Item.prevention_settings = $Item.prevention_settings.settings | Select-Object id, value
                }
                if ($Item.settings.classes) {
                    foreach ($Class in ($Item.settings.classes | Where-Object { $_.exceptions })) {
                        # Remove 'id' from 'exceptions'
                        $Class.exceptions = @($Class.exceptions).foreach{
                            $_.PSObject.Properties.Remove('id')
                            $_
                        }
                    }
                }
                if ($Item.rule_group) {
                    # Keep 'id', 'policy_ids' and 'name' from Firewall rules
                    $Item.rule_group = $Item.rule_group | Select-Object id, policy_ids, name
                }
                if ($Item.settings.settings) {
                    # Keep 'id' and 'value' from settings
                    $Item.settings = $Item.settings.settings | Select-Object id, value
                }
                if ($Item.field_values) {
                    # Keep 'name', 'label', 'type' and 'values' from 'field_values'
                    $Item.field_values = $Item.field_values | Select-Object name, label, type, values
                }
            }
            $Object
        }
        function Get-CidValue ($Item) {
            try {
                # Retrieve existing configurations from CID, excluding 'platform_default'
                $Param = @{
                    Detailed = $true
                    All      = $true
                }
                if ($Item -match 'Policy$') {
                    $Param['Filter'] = "name:!'platform_default'"
                }
                Write-Host "Retrieving '$Item'..."
                Compress-Object (& "Get-Falcon$($Item)" @Param) | Select-Object $ConfigFields.$Item.Import
            } catch {
                throw $_
            }
        }
        function Get-ConfigItem ($Item, $Type, $FilterScript) {
            @($ConfigData.$Item.$Type | Where-Object -FilterScript $FilterScript).foreach{
                Write-Verbose "[Get-ConfigItem] $($Item).$($Type): $($_.id)"
                $_
            }
        }
        function Import-ConfigData ($FilePath) {
            # Load 'FalconConfig' archive into memory
            $Output = @{}
            $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                Get-Content -Path $FilePath -AsByteStream
            } else {
                Get-Content -Path $FilePath -Encoding Byte -Raw
            }
            [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
            $FileStream = New-Object System.IO.MemoryStream
            $FileStream.Write($ByteStream,0,$ByteStream.Length)
            $ConfigArchive = New-Object System.IO.Compression.ZipArchive($FileStream)
            foreach ($FullName in $ConfigArchive.Entries.FullName) {
                # Import Json and remove unnecessary properties
                $Filename = $ConfigArchive.GetEntry($FullName)
                $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
                $Import = ConvertFrom-Json -InputObject ((New-Object System.IO.StreamReader(
                    $Filename.Open())).ReadToEnd())
                $Import = $Import | Select-Object $ConfigFields.$Item.Import
                $Output[$Item] = @{
                    Import = Compress-Object $Import
                }
            }
            if ($FileStream) {
                $FileStream.Dispose()
            }
            $Output
        }
        function Invoke-ConfigArray ($Item) {
            # Find non-existent items and create them in batches of 20
            [array] $Content = if ($Item -match 'Policy$') {
                # Filter to required fields for creating policies
                ,($ConfigData.$Item.Import | Select-Object platform_name, name, description)
            } elseif ($Item -eq 'Ioc') {
                foreach ($Import in $ConfigData.$Item.Import) {
                    $Fields = ($ConfigFields.$Item.Import).foreach{
                        if ($_ -ne 'id' -and $Import.$_) {
                            # Use 'Create' fields that are populated
                            $_
                        }
                    }
                    $Filtered = $Import | Select-Object $Fields
                    if ($Filtered.applied_globally -eq $true) {
                        # Output IOC if 'applied_globally' is true
                        $Filtered
                    } elseif ($Filtered.host_groups) {
                        # Use imported 'id' to find 'name'
                        $Param = @{
                            Item         = 'HostGroup'
                            Type         = 'Import'
                            FilterScript = { $Filtered.host_groups -contains $_.id }
                        }
                        [array] $GroupIds = foreach ($Name in (Get-ConfigItem @Param).Name) {
                            # Use 'name' to find Host Group 'id'
                            $Param = @{
                                Item         = 'HostGroup'
                                Type         = 'Created'
                                FilterScript = { $_.name -eq $Name }
                            }
                            $CreatedId = (Get-ConfigItem @Param).id
                            if ($CreatedId) {
                                ,$CreatedId
                            } elseif ($ForceEnabled -eq $true) {
                                ,(Get-ConfigItem @Param -Type 'Cid').id
                            }
                        }
                        if ($GroupIds) {
                            # Output IOC with updated 'host_groups'
                            $Filtered.host_groups = $GroupIds
                            ,$Filtered
                        } else {
                            Write-Warning ("Unable to create '$($Filtered.type):$($Filtered.value)' " +
                                "[missing_assignment]")
                        }
                    }
                }
            } else {
                # Select fields for 'HostGroup'
                @(Compare-ImportData $Item | Select-Object name, group_type, description, assignment_rule).foreach{
                    # Remove 'assignment_rule' from 'static' host groups
                    if ($_.group_type -eq 'static') {
                        $_.PSObject.Properties.Remove('assignment_rule')
                    }
                    ,$_
                }
            }
            if ($Content) {
                try {
                    for ($i = 0; $i -lt ($Content | Measure-Object).Count; $i += 50) {
                        # Create objects in batches of 50
                        $Request = & "New-Falcon$Item" -Array @($Content[$i..($i + 49)])
                        if ($Request) {
                            if ($ConfigFields.$Item.Import) {
                                $Request | Select-Object $ConfigFields.$Item.Import
                            } else {
                                $Request
                            }
                        }
                    }
                } catch {
                    throw $_
                }
            }
        }
        function Invoke-ConfigItem ($Command, $Content) {
            $Type = $Command -replace '\w+\-Falcon', $null -replace 'Setting', 'Policy'
            try {
                # Create/modify/enable item and notify host
                $Request = & $Command @Content
                if ($Request) {
                    if ($ConfigFields.$Type.Import -and $Type -ne 'FirewallGroup') {
                        # Output 'import' fields, unless creating a firewall rule group
                        $Request | Select-Object $ConfigFields.$Type.Import
                    } else {
                        $Request
                    }
                }
            } catch {
                throw $_
            }
        }
        # Convert 'Path' to absolute and set 'OutputFile'
        $ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $Param = @{
            Path      = (Get-Location).Path
            ChildPath = "FalconConfig_$(Get-Date -Format FileDate).csv"
        }
        $OutputFile = Join-Path @Param
        $ForceEnabled = if ($PSBoundParameters.Force) {
            $true
        } else {
            $false
        }
    }
    process {
        # Create 'ConfigData' and import configuration files
        $ConfigData = Import-ConfigData -FilePath $ArchivePath
        $ConfigData.GetEnumerator().foreach{
            # Retrieve data from CID
            $_.Value['Cid'] = [array] (Get-CidValue $_.Key)
            if ($_.Key -ne 'HostGroup') {
                # Remove existing items from 'Import', except for 'HostGroup'
                $_.Value.Import = Compare-ImportData $_.Key
            }
        }
        if ($ConfigData.SensorUpdatePolicy.Import) {
            $Builds = try {
                Write-Host "Retrieving available sensor builds..."
                Get-FalconBuild
            } catch {
                throw "Failed to retrieve available builds for 'SensorUpdate' policy creation."
            }
            foreach ($Policy in $ConfigData.SensorUpdatePolicy.Import) {
                # Update tagged builds with current tagged build versions
                if ($Policy.settings.build -match '^\d+\|') {
                    $Tag = ($Policy.settings.build -split '\|', 2)[-1]
                    $CurrentBuild = ($Builds | Where-Object { ($_.build -like "*|$Tag") -and
                        ($_.platform -eq $Policy.platform_name) }).build
                    if ($Policy.settings.build -ne $CurrentBuild) {
                        $Policy.settings.build = $CurrentBuild
                    }
                }
                if ($Policy.settings.variants) {
                    # Update tagged 'variant' builds with current tagged build versions
                    @($Policy.settings.variants | Where-Object { $_.build }).foreach{
                        $Tag = ($_.build -split '\|', 2)[-1]
                        $CurrentBuild = ($Builds | Where-Object { ($_.build -like "*|$Tag") -and
                            ($_.platform -eq $Policy.platform_name) }).build
                        if ($_.build -ne $CurrentBuild) {
                            $_.build = $CurrentBuild
                        }
                    }
                }
            }
        }
        foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -eq 'HostGroup' -and $_.Value.Import })) {
            # Create Host Groups
            ($Pair.Value)['Created'] = Invoke-ConfigArray $Pair.Key
            if (($Pair.Value).Created) {
                foreach ($Item in ($Pair.Value).Created) {
                    Write-Host "Created $($Pair.Key) '$($Item.name)'."
                }
            }
        }
        foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^(Ioc|(Ioa|Ml|Sv)Exclusion)$' -and
        $_.Value.Import })) {
            # Create IOCs and exclusions if assigned to 'all' or can be assigned to Host Groups
            if ($Pair.Key -eq 'Ioc') {
                ($Pair.Value)['Created'] = Invoke-ConfigArray $Pair.Key
                if (($Pair.Value).Created) {
                    foreach ($Item in ($Pair.Value).Created) {
                        Write-Host "Created $($Pair.Key) '$($Item.type):$($Item.value)'."
                    }
                }
            } elseif ($Pair.Key -eq 'IoaExclusion') {
                $ConfigData.($Pair.Key)['Created'] = foreach ($Import in $Pair.Value.Import) {
                    # Create Ioa exclusions
                    $Content = @{
                        Name        = $Import.name
                        PatternId   = $Import.pattern_id
                        PatternName = $Import.pattern_name
                        ClRegex     = $Import.cl_regex
                        IfnRegex    = $Import.ifn_regex
                    }
                    @('description', 'comment').foreach{
                        if ($Import.$_) {
                            $Content[$_] = $Import.$_
                        }
                    }
                    if ($Import.groups) {
                        $Content['GroupIds'] = foreach ($Name in $Import.groups.name) {
                            # Get Host Group identifier
                            $Param = @{
                                Item         = 'HostGroup'
                                Type         = 'Created'
                                FilterScript = { $_.name -eq $Name }
                            }
                            $CreatedId = (Get-ConfigItem @Param).id
                            if ($CreatedId) {
                                ,$CreatedId
                            } elseif ($ForceEnabled -eq $true) {
                                ,(Get-ConfigItem @Param -Type 'Cid').id
                            }
                        }
                    }
                    if ($Import.applied_globally -eq $true -or $Content.GroupIds) {
                        $Param = @{
                            Command = "New-Falcon$($Pair.Key)"
                            Content = $Content
                        }
                        $Created = Invoke-ConfigItem @Param
                        if ($Created) {
                            Write-Host "Created $($Pair.Key) '$($Created.name)'."
                        }
                        $Created
                    } else {
                        Write-Warning "Unable to create '$($Content.name)' [missing_assignment]"
                    }
                }
            } else {
                $ConfigData.($Pair.Key)['Created'] = foreach ($Import in $Pair.Value.Import) {
                    # Create Ml/Sv exclusions
                    $Content = @{
                        Value = $Import.value
                    }
                    if ($Import.excluded_from) {
                        $Content['ExcludedFrom'] = $Import.excluded_from
                    }
                    $Content['GroupIds'] = if ($Import.applied_globally -eq $true) {
                        'all'
                    } else {
                        foreach ($Name in $Import.groups.name) {
                            # Get Host Group identifier
                            $Param = @{
                                Item         = 'HostGroup'
                                Type         = 'Created'
                                FilterScript = { $_.name -eq $Name }
                            }
                            $CreatedId = (Get-ConfigItem @Param).id
                            if ($CreatedId) {
                                ,$CreatedId
                            } elseif ($ForceEnabled -eq $true) {
                                ,(Get-ConfigItem @Param -Type 'Cid').id
                            }
                        }
                    }
                    if ($Content.GroupIds) {
                        $Param = @{
                            Command = "New-Falcon$($Pair.Key)"
                            Content = $Content
                        }
                        $Created = Invoke-ConfigItem @Param
                        if ($Created) {
                            Write-Host "Created $($Pair.Key) '$($Created.value)'."
                        }
                        $Created
                    } else {
                        Write-Warning "Unable to create '$($Content.value)' [missing_assignment]"
                    }
                }
            }
        }
        if ($ConfigData.FirewallGroup.Import) {
            # Create Firewall Rule Groups
            $ConfigData.FirewallGroup['Created'] = foreach ($Import in $ConfigData.FirewallGroup.Import) {
                # Set required fields
                $Content = @{
                    Name    = $Import.name
                    Enabled = $Import.enabled
                }
                switch ($Import) {
                    # Add optional fields
                    { $_.description } { $Content['Description'] = $_.description }
                    { $_.comment }     { $Content['Comment'] = $_.comment }
                }
                if ($Import.rule_ids) {
                    # Select required fields for each individual rule
                    $CreateFields = $ConfigFields.FirewallRule.Import | Where-Object { $_ -ne 'id' -and
                        $_ -ne 'family' }
                    $Rules = $ConfigData.FirewallRule.Import | Where-Object {
                        $Import.rule_ids -contains $_.family } | Select-Object $CreateFields
                    @($Rules).foreach{
                        if ($_.name.length -gt 64) {
                            # Trim rule names to 64 characters
                            $_.name = ($_.name).SubString(0,63)
                        }
                    }
                    $Content['Rules'] = $Rules
                }
                $Param = @{
                    Command = 'New-FalconFirewallGroup'
                    Content = $Content
                }
                $NewGroup = Invoke-ConfigItem @Param
                if ($NewGroup) {
                    # Output object with 'id' and 'name'
                    [PSCustomObject] @{
                        id   = $NewGroup
                        name = $Import.name
                    }
                    $Message = "Created FirewallGroup '$($Import.name)'"
                    if ($Rules) {
                        $Message += " with $(($Rules | Measure-Object).Count) rules"
                    }
                    Write-Host "$Message."
                }
            }
        }
        if ($ConfigData.IoaGroup.Import) {
            # Create IOA Rule groups
            $ConfigData.IoaGroup['Created'] = foreach ($Import in $ConfigData.IoaGroup.Import) {
                # Set required fields
                $Content = @{
                    Platform = $Import.platform
                    Name     = $Import.name
                }
                switch ($Import) {
                    # Add optional fields
                    { $_.description } { $Content['Description'] = $_.description }
                    { $_.comment }     { $Content['Comment'] = $_.comment }
                }
                $Param = @{
                    Command = 'New-FalconIoaGroup'
                    Content = $Content
                }
                $NewGroup = Invoke-ConfigItem @Param
                if ($NewGroup) {
                    Write-Host "Created $($NewGroup.platform) IoaGroup '$($NewGroup.name)'."
                    # Get date for adding 'comment' fields
                    $FileDate = Get-Date -Format FileDate
                    if ($Import.rules) {
                        $NewRules = Compress-Object ($Import.rules | Select-Object $ConfigFields.IoaRule.Create)
                        if ($NewRules) {
                            $NewGroup.rules = foreach ($Rule in $NewRules) {
                                # Create IOA Rule within IOA Group
                                $Content = @{
                                    RulegroupId     = $NewGroup.id
                                    Name            = $Rule.name
                                    PatternSeverity = $Rule.pattern_severity
                                    RuletypeId      = $Rule.ruletype_id
                                    DispositionId   = $Rule.disposition_id
                                    FieldValues     = $Rule.field_values
                                }
                                @('description', 'comment').foreach{
                                    if ($Rule.$_) {
                                        $Content[$_] = $Rule.$_
                                    }
                                }
                                $Param = @{
                                    Command = 'New-FalconIoaRule'
                                    Content = $Content
                                }
                                $Created = Invoke-ConfigItem @Param
                                if ($Created) {
                                    Write-Host "Created IoaRule '$($Created.name)'."
                                }
                                if ($Created.enabled -eq $false -and $Rule.enabled -eq $true) {
                                    # Enable IOA Rule
                                    $Created.enabled = $true
                                    $Param = @{
                                        Command = 'Edit-FalconIoaRule'
                                        Content = @{
                                            RulegroupId      = $NewGroup.id
                                            RuleUpdates      = $Created
                                            Comment          = if ($Rule.comment) {
                                                $Rule.comment
                                            } else {
                                                "Enabled $FileDate by 'Import-FalconConfig'"
                                            }
                                        }
                                    }
                                    $Enabled = Invoke-ConfigItem @Param
                                    if ($Enabled) {
                                        # Output enable rule request result
                                        $Enabled
                                        Write-Host "Enabled IoaRule '$($Created.name)'."
                                    }
                                } else {
                                    # Output create rule request result
                                    $Created
                                }
                            }
                        }
                    }
                    if ($Import.enabled -eq $true) {
                        # Enable IOA Group
                        $Param = @{
                            Command = 'Edit-FalconIoaGroup'
                            Content = @{
                                Id               = $NewGroup.id
                                Name             = $NewGroup.name
                                Enabled          = $true
                                Description      = if ($NewGroup.description) {
                                    $NewGroup.description
                                } else {
                                    "Imported $FileDate by 'Import-FalconConfig'"
                                }
                                Comment = if ($NewGroup.comment) {
                                    $NewGroup.comment
                                } else {
                                    "Enabled $FileDate by 'Import-FalconConfig'"
                                }
                            }
                        }
                        $Enabled = Invoke-ConfigItem @Param
                        if ($Enabled) {
                            # Output enabled result
                            $Enabled
                            Write-Host "Enabled IoaGroup '$($Enabled.name)'."
                        }
                    } else {
                        # Output group creation result
                        $NewGroup
                    }
                }
            }
        }
        foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^.*Policy$' -and $_.Value.Import })) {
            # Create policies
            $Created = Invoke-ConfigArray -Item $Pair.Key
            if ($Created) {
                foreach ($Item in $Created) {
                    Write-Host "Created $($Item.platform_name) $($Pair.Key) '$($Item.name)'."
                }
                $ConfigData.($Pair.Key)['Created'] = foreach ($Policy in $Created) {
                    $Param = @{
                        Item = $Pair.Key
                        Type = 'Import'
                        FilterScript = { $_.platform_name -eq $Policy.platform_name -and $_.name -eq $Policy.name }
                    }
                    $Import = Get-ConfigItem @Param
                    if ($Import.settings -or $Import.prevention_settings) {
                        if ($Pair.Key -eq 'FirewallPolicy') {
                            # Update 'FirewallPolicy' with settings
                            $Content = @{
                                PolicyId        = $Policy.id
                                PlatformId      = $Import.settings.platform_id
                                Enforce         = $Import.settings.enforce
                                DefaultInbound  = $Import.settings.default_inbound
                                DefaultOutbound = $Import.settings.default_outbound
                                MonitorMode     = $Import.settings.test_mode
                            }
                            [array] $RuleGroupIds = if ($Import.settings.rule_group_ids) {
                                # Using 'rule_group_id', match 'name' of imported group
                                $Param = @{
                                    Item         = 'FirewallGroup'
                                    Type         = 'Import'
                                    FilterScript = { $Import.settings.rule_group_ids -contains $_.id }
                                }
                                $GroupNames = (Get-ConfigItem @Param).name
                                foreach ($Name in $GroupNames) {
                                    $Param = @{
                                        Item         = 'FirewallGroup'
                                        Type         = 'Created'
                                        FilterScript = { $_.Name -eq $Name }
                                    }
                                    # Match 'name' to created rule group id
                                    ,(Get-ConfigItem @Param).id
                                }
                            }
                            if ($RuleGroupIds) {
                                # Add created Rule Groups
                                $Content['RuleGroupIds'] = $RuleGroupIds
                            }
                            $Param = @{
                                Command = 'Edit-FalconFirewallSetting'
                                Content = $Content
                            }
                            @(Invoke-ConfigItem @Param).foreach{
                                if ($_.writes.resources_affected -eq 1) {
                                    # Append 'settings' to 'FirewallPolicy'
                                    Add-Property -Object $Policy -Name 'settings' -Value $Import.settings
                                    Write-Host "Applied settings to $($Pair.Key) '$($Policy.name)'."
                                }
                            }
                        } else {
                            # Update policies with settings
                            $Param = @{
                                Command = "Edit-Falcon$($Pair.Key)"
                                Content = @{
                                    Id       = $Policy.id
                                    Settings = if ($Import.prevention_settings) {
                                        $Import.prevention_settings
                                    } else {
                                        $Import.settings
                                    }
                                }
                            }
                            @(Invoke-ConfigItem @Param).foreach{
                                if ($_.settings -or $_.prevention_settings) {
                                    Write-Host "Applied settings to $($Pair.Key) '$($Policy.name)'."
                                }
                            }
                        }
                    }
                    if ($Pair.Key -eq 'PreventionPolicy') {
                        foreach ($IoaGroup in $Import.ioa_rule_groups) {
                            # Assign IOA rule groups to Prevention policies
                            $Param = @{
                                Item         = 'IoaGroup'
                                Type         = 'Created'
                                FilterScript = { $_.name -eq $IoaGroup.name }
                            }
                            $IoaGroupCreatedId = (Get-ConfigItem @Param).id
                            $IoaGroupId = if ($IoaGroupCreatedId) {
                                $IoaGroupCreatedId
                            } elseif ($ForceEnabled -eq $true) {
                                (Get-ConfigItem @Param -Type 'Cid').id
                            }
                            if ($IoaGroupId) {
                                $Param = @{
                                    Command = "Invoke-Falcon$($Pair.Key)Action"
                                    Content = @{
                                        Name    = 'add-rule-group'
                                        Id      = $Policy.id
                                        GroupId = $IoaGroupId
                                    }
                                }
                                @(Invoke-ConfigItem @Param).foreach{
                                    if ($_.ioa_rule_groups) {
                                        # Update 'ioa_rule_groups' for policy
                                        $Policy.ioa_rule_groups = $_.ioa_rule_groups
                                        Write-Host ("Assigned '$($IoaGroup.name)' to $($Pair.Key) " +
                                            "'$($Policy.name)'.")
                                    }
                                }
                            }
                        }
                    }
                    foreach ($HostGroup in $Import.groups) {
                        # Assign host groups to policies
                        $Param = @{
                            Item         = 'HostGroup'
                            Type         = 'Created'
                            FilterScript = { $_.name -eq $HostGroup.name }
                        }
                        $HostGroupCreatedId = (Get-ConfigItem @Param).id
                        $HostGroupId = if ($HostGroupCreatedId) {
                            $HostGroupCreatedId
                        } elseif ($ForceEnabled -eq $true) {
                            (Get-ConfigItem @Param -Type 'Cid').id
                        }
                        if ($HostGroupId) {
                            $Param = @{
                                Command = "Invoke-Falcon$($Pair.Key)Action"
                                Content = @{
                                    Name    = 'add-host-group'
                                    Id      = $Policy.id
                                    GroupId = $HostGroupId
                                }
                            }
                            @(Invoke-ConfigItem @Param).foreach{
                                if ($_.groups) {
                                    # Update 'group' for policy
                                    $Policy.groups = $_.groups
                                    Write-Host "Assigned '$($HostGroup.name)' to $($Pair.Key) '$($Policy.name)'."
                                }
                            }
                        }
                    }
                    if ($Import.enabled -eq $true -and $Policy.enabled -eq $false) {
                        $Param = @{
                            Command = "Invoke-Falcon$($Pair.Key)Action"
                            Content = @{
                                Id   = $Policy.id
                                Name = 'enable'
                            }
                        }
                        @(Invoke-ConfigItem @Param).foreach{
                            if ($_.enabled -eq $true) {
                                # Update 'enabled' for policy
                                $Policy.enabled = $_.enabled
                                Write-Host "Enabled $($Pair.Key) '$($Policy.Name)'."
                            }
                        }
                    }
                    # Output updated policy
                    $Policy
                }
            }
        }
        foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^.*Policy$' })) {
            if ($Pair.Value.Created -and $Pair.Value.Cid) {
                # Output precedence warning if existing policies were found in CID
                Write-Warning "Existing '$($Pair.Key)' items were found. Verify precedence!"
            }
        }
    }
    end {
        if ($PSBoundParameters.Debug) {
            $ConfigData
        } elseif ($ConfigData.Values.Created) {
            foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Value.Created })) {
                @($Pair.Value.Created).foreach{
                    # Output 'created' results to CSV
                    [PSCustomObject] @{
                        type = $Pair.Key
                        id = if ($_.instance_id) {
                            $_.instance_id
                        } else {
                            $_.id
                        }
                        name = if ($_.type -and $_.value) {
                            "$($_.type):$($_.value)"
                        } elseif ($_.value) {
                            $_.value
                        } else {
                            $_.name
                        }
                        platform_name = if ($_.platform_name) {
                            $_.platform_name
                        } elseif ($_.platform) {
                            $_.platform
                        } else {
                            $null
                        }
                    } | Export-Csv -Path $OutputFile -NoTypeInformation -Append
                }
            }
            if (Test-Path $OutputFile) {
                Get-ChildItem -Path $OutputFile
            }
        } else {
            Write-Warning 'No items created.'
        }
    }
}