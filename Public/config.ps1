function Export-Config {
    <#
    .SYNOPSIS
        Create an archive containing exported CrowdStrike Falcon configuration files.
    .DESCRIPTION
        Uses various PSFalcon commands to gather and export Groups, Policies and Exclusions as a collection
        of Json files contained with in a zip archive. The exported files can be used with 'Import-FalconConfig'
        to restore configurations to your existing environment, or create copies in another environment.
    .PARAMETER ITEMS
        Items to export from your current CID. Leave unspecified to export the entire list.
    .EXAMPLE
        PS> Export-FalconConfig

        Creates '.\FalconConfig_<FileDateTime>.zip' with all available configuration files.
    .EXAMPLE
        PS> Export-FalconConfig -Items HostGroup, FirewallGroup, FirewallPolicy

        Creates '.\FalconConfig_<FileDateTime>.zip' with HostGroup, FirewallGroup (including Firewall Rules),
        and FirewallPolicy configuration files.
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'config:Export')]
    [OutputType([object])]
    param(
        [Parameter(Position = 1,
            ParameterSetName = 'config:Export')]
        [ValidateSet('HostGroup', 'IOAGroup', 'FirewallGroup', 'DeviceControlPolicy', 'FirewallPolicy',
        'PreventionPolicy', 'ResponsePolicy', 'SensorUpdatePolicy', 'IOAExclusion', 'MLExclusion', 'SVExclusion')]
        [array] $Items
    )
    DynamicParam {
        $Endpoints = @('config:Export')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Get current location
        $CurrentPath = (Get-Location).Path
        # Set output filename
        $OutputFile = "FalconConfig_$(Get-Date -Format FileDateTime).zip"
        function Get-ItemContent ($Item) {
            # Request content using selected command
            Write-Host "Exporting '$Item'..."
            $FilePath = Join-Path -Path $CurrentPath -ChildPath "$Item.json"
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
                ConvertTo-Json -InputObject @( $FileContent ) -Depth 16 | Out-File -FilePath $FilePath -Append
                $FilePath
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-Help $MyInvocation.MyCommand.Name -Detailed
        } else {
            $Export = if ($PSBoundParameters.Items) {
                # Use specified items
                $PSBoundParameters.Items
            } else {
                # Use all available items
                (Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({ $_.Name -eq
                'config:Export' }).Parameters.Where({ $_.Name -eq 'Items' }).Attributes.ValidValues
            }
            [array] $Export += switch ($Export) {
                { $_ -match '^(IOA|ML|SV)Exclusion$' -and $Export -notcontains 'HostGroup' } {
                    'HostGroup'
                }
                { $_ -contains 'FirewallGroup' } {
                    'FirewallRule'
                }
            }
            $JsonFiles = foreach ($Item in $Export) {
                # Retrieve results and export to Json
                ,(Get-ItemContent -Item $Item)
            }
            if ($JsonFiles) {
                # Archive Json exports with content
                $ArchivePath = Join-Path -Path $CurrentPath -ChildPath $OutputFile
                $Param = @{
                    Path = (Get-ChildItem | Where-Object {
                        ($JsonFiles -contains $_.FullName) -and ($_.Length -gt 0) }).FullName
                    DestinationPath = $ArchivePath
                }
                Compress-Archive @Param
            }
        }
    }
    end {
        if ($OutputArchive) {
            $OutputArchive.Dispose()
        }
        if ($ArchivePath) {
            if (Test-Path $ArchivePath) {
                # Remove Json files and output archive
                Remove-Item -Path $JsonFiles -Force
                Get-ChildItem $ArchivePath
            }
        } elseif ($JsonFiles) {
            if (Test-Path $JsonFiles) {
                # Output list of temporary files
                Get-ChildItem $JsonFiles
            }
        }
    }
}
function Import-Config {
    <#
    .SYNOPSIS
        Import configurations from a 'FalconConfig' archive into your Falcon environment.
    .DESCRIPTION
        Creates groups, policies, exclusions and rules within a 'FalconConfig' archive within your authenticated
        Falcon environment. Anything that already exists will be ignored and no existing items will be modified.
    .PARAMETER PATH
        File path of the target 'FalconConfig' archive
    .EXAMPLE
        PS> Import-FalconConfig -Path .\FalconConfig_<FileDateTime>.zip

        Creates new items present in the archive, but does not assign policies or exclusions to existing groups or
        modify existing items (including 'default' policies).
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'config:Import')]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true,
            Position = 1,
            ParameterSetName = 'config:Import')]
        [ValidatePattern("\.zip$")]
        [string] $Path
    )
    DynamicParam {
        $Endpoints = @('config:Import')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        # List of fields to capture during Json import
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
            IOAExclusion = @{
                Import = @('id', 'cl_regex', 'ifn_regex', 'name', 'pattern_id', 'pattern_name', 'groups',
                    'comment', 'description')
            }
            IOAGroup = @{
                Import = @('id', 'platform', 'name', 'description', 'rules', 'enabled', 'version')
                Compare = @('platform', 'name')
            }
            IOARule = @{
                Create = @('name', 'pattern_severity', 'ruletype_id', 'disposition_id', 'field_values',
                    'description', 'comment', 'enabled')
                Export = @('instance_id', 'name')
            }
            MLExclusion = @{
                Import = @('id', 'value', 'excluded_from', 'groups', 'applied_globally')
                Compare = @('value')
                Export = @('id', 'value')
            }
            PreventionPolicy = @{
                Import = @('id', 'platform_name', 'name', 'description', 'prevention_settings',
                    'enabled', 'groups')
            }
            ResponsePolicy = @{
                Import = @('id', 'platform_name', 'name', 'description', 'settings', 'enabled', 'groups')
            }
            SensorUpdatePolicy = @{
                Import = @('id', 'platform_name', 'name', 'settings', 'enabled', 'description',
                    'groups')
            }
            SVExclusion = @{
                Import = @('id', 'value', 'groups', 'applied_globally')
                Compare = @('value')
            }
        }
        function Add-Field ($Object, $Name, $Value) {
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Compress-Reference ($Object) {
            # Remove unnecessary fields from sub-objects before import
            foreach ($Item in $Object) {
                if ($Item.group_type -eq 'static' -and $Item.assignment_rule) {
                    # Remove assignment_rule values from static Host Groups
                    $Item.PSObject.Properties.Remove('assignment_rule')
                }
                if ($Item.groups) {
                    # Exclude fields except id and name with group info
                    $Item.groups = $Item.groups | Select-Object id, name
                }
                if ($Item.prevention_settings.settings) {
                    # Exclude fields except id and value with prevention settings
                    $Item.prevention_settings = $Item.prevention_settings.settings | Select-Object id, value
                }
                if ($Item.settings.classes) {
                    foreach ($Class in ($Item.settings.classes | Where-Object { $_.exceptions })) {
                        # Exclude ids for individual Device Control exceptions
                        $Class.exceptions = $Class.exceptions | ForEach-Object {
                            $_.PSObject.Properties.Remove('id')
                            $_
                        }
                    }
                }
                if ($Item.rule_group) {
                    # Exclude rule_group fields except id, policy_ids and name with Firewall rules
                    $Item.rule_group = $Item.rule_group | Select-Object id, policy_ids, name
                }
                if ($Item.settings.settings) {
                    # Exclude fields except id and value with settings
                    $Item.settings = $Item.settings.settings | Select-Object id, value
                }
                if ($Item.field_values) {
                    # Exclude non-required fields from IOA Rules
                    $Item.field_values = $Item.field_values | Select-Object name, label, type, values
                }
            }
            $Object
        }
        function Get-ConfigItem ($Item, $Type, $FilterScript) {
            # Retrieve an item from 'ConfigData'
            $ConfigData.$Item.$Type | Where-Object -FilterScript $FilterScript
        }
        function Get-ImportData ($Item) {
            if ($ConfigData.$Item.CID) {
                # Compare imported items against CID
                $Param = @{
                    ReferenceObject = $ConfigData.$Item.Import
                    DifferenceObject = $ConfigData.$Item.CID
                    Property = if ($ConfigFields.$Item.Compare) {
                        # Use defined fields for comparison
                        $ConfigFields.$Item.Compare
                    } elseif ($Item -match '^*.Policy$') {
                        # Use 'platform_name' and 'name' for policies
                        @('platform_name', 'name')
                    } else {
                        # Use 'name'
                        'name'
                    }
                }
                foreach ($Result in (Compare-Object @Param)) {
                    $ScriptBlock = switch ($Item) {
                        { $_ -eq 'IOAGroup' } {
                            # Output IOA groups from import using 'platform' and 'name' match
                            { $_.platform -eq $Result.platform -and $_.name -eq $Result.name }
                        }
                        { $_ -like '*Exclusion' } {
                            # Output exclusions from import using 'value' match
                            { $_.value -eq $Result.value }
                        }
                        { $_ -like '*Policy' } {
                            # Output policies from import using 'platform_name' and 'name'
                            { $_.platform_name -eq $Result.platform_name -and $_.name -eq $Result.name }
                        }
                        default {
                            # Output using 'name'
                            { $_.name -eq $Result.name }
                        }
                    }
                    $Param = @{
                        Item = $Item
                        Type = 'Import'
                        FilterScript = $ScriptBlock
                    }
                    Get-ConfigItem @Param
                }
            } elseif ($ConfigData.$Item.Import) {
                # Output all items
                $ConfigData.$Item.Import
            }
        }
        function Get-Reference ($Item) {
            try {
                # Retrieve existing configurations from CID, excluding 'platform_default'
                $Param = @{
                    Detailed = $true
                    All = $true
                }
                if ($Item -match 'Policy') {
                    $Param['Filter'] = "name:!'platform_default'"
                }
                Write-Host "Retrieving '$Item'..."
                Compress-Reference -Object (& "Get-Falcon$($Item)" @Param | Where-Object { $_.name -ne
                    'platform_default' } | Select-Object $ConfigFields.$Item.Import)
            } catch {
                throw $_
            }
        }
        function Import-ConfigData ($FilePath) {
            # Load configuration archive into memory, extract files and convert from Json
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
                $Filename = $ConfigArchive.GetEntry($FullName)
                $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
                $Output[$Item] = @{
                    Import = (New-Object System.IO.StreamReader($Filename.Open())).ReadToEnd() | ConvertFrom-Json
                }
            }
            if ($FileStream) {
                $FileStream.Dispose()
            }
            ($Output.GetEnumerator()).foreach{
                # Remove unnecessary fields and retrieve existing CID configuration
                $_.Value.Import = Compress-Reference -Object $_.Value.Import
                $_.Value['CID'] = [array] (Get-Reference -Item $_.Key)
            }
            $Output
        }
        function Invoke-ConfigArray ($Item) {
            # Find non-existent items and create them in batches of 20
            $ImportData = Get-ImportData -Item $Item
            if ($ImportData) {
                $Content = if ($Item -match '^.*Policy$') {
                    $ImportData | Select-Object platform_name, name, description
                } else {
                    $ImportData | Select-Object name, group_type, description, assignment_rule | ForEach-Object {
                        if ($_.group_type -eq 'static') {
                            $_.PSObject.Properties.Remove('assignment_rule')
                        }
                        $_
                    }
                }
                try {
                    for ($i = 0; $i -lt $Content.count; $i += 20) {
                        $Param = @{
                            Array = @($Content)[$i..($i + 19)]
                        }
                        $Request = & "New-Falcon$Item" @Param
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
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-Help $MyInvocation.MyCommand.Name -Detailed
        } else {
            #  Create 'ConfigData' and import configuration files
            $ConfigData = Import-ConfigData -FilePath $PSBoundParameters.Path
            if ($ConfigData.SensorUpdatePolicy.Import) {
                $Builds = try {
                    Write-Host "Retrieving available sensor builds..."
                    Get-FalconBuild
                } catch {
                    throw "Failed to retrieve available builds for SensorUpdate policy creation."
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
                }
            }
            if ($ConfigData.HostGroup.Import) {
                # Create Host Groups
                $Created = Invoke-ConfigArray -Item 'HostGroup'
                if ($Created) {
                    $ConfigData.HostGroup['Created'] = $Created
                    foreach ($Item in $Created) {
                        Write-Host "Created HostGroup '$($Item.name)'."
                    }
                }
            }
            if ($ConfigData.FirewallGroup.Import) {
                # Create Firewall Rule Groups
                $ImportData = Get-ImportData -Item 'FirewallGroup'
                if ($ImportData) {
                    $ConfigData.FirewallGroup['Created'] = foreach ($Import in $ImportData) {
                        # Set required fields
                        $Content = @{
                            Name = $Import.name
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
                            $Rules | ForEach-Object {
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
                                id = $NewGroup
                                name = $Import.name
                            }
                            $Message = "Created FirewallGroup '$($Import.name)'"
                            if ($Rules) {
                                $Message += " with $($Rules.count) rules"
                            }
                            Write-Host "$Message."
                        }
                    }
                }
            }
            if ($ConfigData.IOAGroup.Import) {
                # Create IOA Rule groups
                $ImportData = Get-ImportData -Item 'IOAGroup'
                if ($ImportData) {
                    $ConfigData.IOAGroup['Created'] = foreach ($Import in $ImportData) {
                        # Set required fields
                        $Content = @{
                            Platform = $Import.platform
                            Name = $Import.name
                        }
                        switch ($Import) {
                            # Add optional fields
                            { $_.description } { $Content['Description'] = $_.description }
                            { $_.comment }     { $Content['Comment'] = $_.comment }
                        }
                        $Param = @{
                            Command = 'New-FalconIOAGroup'
                            Content = $Content
                        }
                        $NewGroup = Invoke-ConfigItem @Param
                        if ($NewGroup) {
                            Write-Host "Created $($NewGroup.platform) IOAGroup '$($NewGroup.name)'."
                            # Get date for adding 'comment' fields
                            $FileDate = Get-Date -Format FileDate
                            if ($Import.rules) {
                                $NewRules = Compress-Reference -Object $Import.rules |
                                    Select-Object $ConfigFields.IOARule.Create
                                if ($NewRules) {
                                    $NewGroup.rules = foreach ($Rule in $NewRules) {
                                        # Create IOA Rule within IOA Group
                                        $Content = @{
                                            RulegroupId = $NewGroup.id
                                            Name = $Rule.name
                                            PatternSeverity = $Rule.pattern_severity
                                            RuletypeId = $Rule.ruletype_id
                                            DispositionId = $Rule.disposition_id
                                            FieldValues = $Rule.field_values
                                        }
                                        @('description', 'comment').foreach{
                                            if ($Rule.$_) {
                                                $Content[$_] = $Rule.$_
                                            }
                                        }
                                        $Param = @{
                                            Command = 'New-FalconIOARule'
                                            Content = $Content
                                        }
                                        $Created = Invoke-ConfigItem @Param
                                        if ($Created) {
                                            Write-Host "Created IOARule '$($Created.name)'."
                                        }
                                        $Enabled = if ($Created.enabled -eq $false -and $Rule.enabled -eq $true) {
                                            # Enable IOA Rule
                                            $Created.enabled = $true
                                            $Version = [string] (Get-FalconIOAGroup -Ids ($NewGroup.id)).version
                                            if ($Version) {
                                                $Param = @{
                                                    Command = 'Edit-FalconIOARule'
                                                    Content = @{
                                                        RulegroupId = $NewGroup.id
                                                        RuleUpdates = $Created
                                                        RulegroupVersion = $Version
                                                        Comment = if ($Rule.comment) {
                                                            $Rule.comment
                                                        } else {
                                                            "Enabled $FileDate"
                                                        }
                                                    }
                                                }
                                                Invoke-ConfigItem @Param
                                            }
                                        }
                                        if ($Enabled) {
                                            # Output enable rule request result
                                            $Enabled
                                            Write-Host "Enabled IOARule '$($Created.name)'."
                                        } else {
                                            # Output create rule request result
                                            $Created
                                        }
                                    }
                                }
                            }
                            $Enabled = if ($Import.enabled -eq $true) {
                                # Enable IOA Group
                                $Version = [string] (Get-FalconIOAGroup -Ids $NewGroup.id).version
                                if ($Version) {
                                    $Param = @{
                                        Command = 'Edit-FalconIOAGroup'
                                        Content = @{
                                            Id = $NewGroup.id
                                            Name = $NewGroup.name
                                            Enabled = $true
                                            RulegroupVersion = $Version
                                            Description = if ($NewGroup.description) {
                                                $NewGroup.description
                                            } else {
                                                "Imported $FileDate"
                                            }
                                            Comment = if ($NewGroup.comment) {
                                                $NewGroup.comment
                                            } else {
                                                "Enabled $FileDate"
                                            }
                                        }
                                    }
                                    Invoke-ConfigItem @Param
                                }
                            }
                            if ($Enabled) {
                                # Output group enabled result
                                $Enabled
                                Write-Host "Enabled IOAGroup '$($Enabled.name)'."
                            } else {
                                # Output group creation result
                                $NewGroup
                            }
                        }
                    }
                }
            }
            foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^(ML|SV)Exclusion$' })) {
                # Create exclusions if corresponding Host Groups were created, or assigned to 'all'
                $ImportData = Get-ImportData -Item $Pair.Key
                if ($ImportData) {
                    $ConfigData.($Pair.Key)['Created'] = foreach ($Import in $ImportData) {
                        $Content = @{
                            Value = $Import.value
                        }
                        if ($Import.excluded_from) {
                            $Content['ExcludedFrom'] = $Import.excluded_from
                        }
                        $Content['GroupIds'] = if ($Import.applied_globally -eq $true) {
                            'all'
                        } elseif ($ConfigData.HostGroup.Created.id) {
                            foreach ($Name in $Import.groups.name) {
                                # Get created Host Group identifiers
                                $Param = @{
                                    Item = 'HostGroup'
                                    Type = 'Created'
                                    FilterScript = { $_.name -eq $Name }
                                }
                                (Get-ConfigItem @Param).id
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
                        }
                    }
                }
            }
            foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^.*Policy$' })) {
                # Create Policies
                $Created = Invoke-ConfigArray -Item $Pair.Key
                if ($Created) {
                    foreach ($Item in $Created) {
                        Write-Host "Created $($Item.platform_name) $($Pair.Key) '$($Item.name)'."
                    }
                    $ConfigData.($Pair.Key)['Created'] = foreach ($Policy in $Created) {
                        $Param = @{
                            Item = $Pair.Key
                            Type = 'Import'
                            FilterScript = { $_.platform_name -eq $Policy.platform_name -and $_.name -eq
                                $Policy.name }
                        }
                        $Import = Get-ConfigItem @Param
                        if ($Import.settings -or $Import.prevention_settings) {
                            if ($Pair.Key -eq 'FirewallPolicy') {
                                # Update Firewall policies with settings
                                $Content = @{
                                    PolicyId = $Policy.id
                                    PlatformId = $Import.settings.platform_id
                                    Enforce = $Import.settings.enforce
                                    DefaultInbound = $Import.settings.default_inbound
                                    DefaultOutbound = $Import.settings.default_outbound
                                    MonitorMode = $Import.settings.test_mode
                                }
                                $RuleGroupIds = if ($Import.settings.rule_group_ids) {
                                    # Using 'rule_group_id', match 'name' of imported group to created group
                                    $Param = @{
                                        Item = 'FirewallGroup'
                                        Type = 'Import'
                                        FilterScript = { $Import.settings.rule_group_ids -contains $_.id }
                                    }
                                    $GroupNames = (Get-ConfigItem @Param).name
                                    foreach ($Name in $GroupNames) {
                                        $Param = @{
                                            Item = 'FirewallGroup'
                                            Type = 'Created'
                                            FilterScript = { $_.Name -eq $Name }
                                        }
                                        # Match 'name' to find created rule group id
                                        (Get-ConfigItem @Param).id
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
                                $Request = Invoke-ConfigItem @Param
                                if ($Request.resources_affected -eq 1) {
                                    # Append 'settings' to policy
                                    Add-Field -Object $Policy -Name 'settings' -Value $Import.settings
                                }
                            } else {
                                # Update other policies with settings
                                $Param = @{
                                    Command = "Edit-Falcon$($Pair.Key)"
                                    Content = @{
                                        Id = $Policy.id
                                        Settings = if ($Import.prevention_settings) {
                                            $Import.prevention_settings
                                        } else {
                                            $Import.settings
                                        }
                                    }
                                }
                                $Request = Invoke-ConfigItem @Param
                                @('settings', 'prevention_settings').foreach{
                                    if ($Request.$_) {
                                        # Update 'settings' on policy
                                        $Policy.$_ = $Request.$_
                                    }
                                }
                            }
                            if ($Request) {
                                Write-Host "Applied settings to $($Pair.Key) '$($Policy.name)'."
                            }
                        }
                        foreach ($Group in $Import.groups) {
                            $Param = @{
                                Item = 'HostGroup'
                                Type = 'Created'
                                FilterScript = { $_.name -eq $Group.name }
                            }
                            $GroupId = (Get-ConfigItem @Param).id
                            if ($GroupId) {
                                # Assign group to policy
                                $Param = @{
                                    Command = "Invoke-Falcon$($Pair.Key)Action"
                                    Content = @{
                                        Name = "add-host-group"
                                        Id = $Policy.id
                                        GroupId = $GroupId
                                    }
                                }
                                $Request = Invoke-ConfigItem @Param
                                if ($Request.groups) {
                                    # Update 'group' on policy
                                    $Policy.groups = $Request.groups
                                    Write-Host ("Assigned HostGroup '$($Group.name)' to $($Pair.Key) " +
                                        "'$($Policy.name)'.")
                                }
                            }
                        }
                        <# Future code for assigning custom IOA Rule Groups to Prevention policies
                        foreach ($Group in $Import.unknown_property) {
                            # Assign IOA Rule Groups to Prevention policies
                            $Param = @{
                                Item = 'IOAGroup'
                                Type = 'Created'
                                FilterScript = { $_.name -eq $Group.name }
                            }
                            $GroupId = (Get-ConfigItem @Param).id
                            if ($GroupId) {
                                # Assign group to policy
                                $Param = @{
                                    Command = "Invoke-Falcon$($Pair.Key)Action"
                                    Content = @{
                                        Name = "add-rule-group"
                                        Id = $Policy.id
                                        GroupId = $GroupId
                                    }
                                }
                                $Request = Invoke-ConfigItem @Param
                                if ($Request.unknown_property) {
                                    # Update 'group' on policy
                                    $Policy.unknown_property = $Request.unknown_property
                                }
                            }
                        }
                        #>
                        if ($Import.enabled -eq $true -and $Policy.enabled -eq $false) {
                            $Param = @{
                                Command = "Invoke-Falcon$($Pair.Key)Action"
                                Content = @{
                                    Id = $Policy.id
                                    Name = 'enable'
                                }
                            }
                            $Request = Invoke-ConfigItem @Param
                            if ($Request) {
                                # Update 'enabled' status on policy
                                $Policy.enabled = $Request.enabled
                                Write-Host "Enabled $($Pair.Key) '$($Policy.Name)'."
                            }
                        }
                        # Output updated policy
                        $Policy
                    }
                }
            }
        }
    }
    end {
        if (!$PSBoundParameters.Help -and $ConfigData) {
            $Param = @{
                Path = (Get-Location).Path
                ChildPath = "FalconConfig_$(Get-Date -Format FileDateTime).csv"
            }
            $OutputFile = Join-Path @Param
            foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Value.Created })) {
                $Pair.Value.Created | ForEach-Object {
                    # Output 'created' results to CSV
                    [PSCustomObject] @{
                        type = $Pair.Key
                        id = if ($_.instance_id) {
                            $_.instance_id
                        } else {
                            $_.id
                        }
                        name = if ($_.value) {
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
        }
    }
}