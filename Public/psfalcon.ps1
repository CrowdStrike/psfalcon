function Export-FalconReport {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [ValidatePattern('\.csv$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path,

        [Parameter(Mandatory = $true, ValueFromPipeLine = $true, Position = 2)]
        [object] $Object
    )
    begin {
        if ($PSBoundParameters.Path) {
            $OutputPath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        }
        function Get-Array ($Array, $Output, $Name) {
            foreach ($Item in $Array) {
                if ($Item.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                    # Add sub-objects to output
                    $IdField = $Item.PSObject.Properties.Name -match '^(id|(device|policy)_id)$'
                    if ($IdField) {
                        $ObjectParam = @{
                            Object = $Item | Select-Object -ExcludeProperty $IdField
                            Output = $Output
                            Prefix = "$($Name).$($Item.$IdField)"
                        }
                        Get-PSObject @ObjectParam
                    } else {
                        $ObjectParam = @{
                            Object = $Item
                            Output = $Output
                            Prefix = $Name
                        }
                        Get-PSObject @ObjectParam
                    }
                } else {
                    # Add property to output as 'name'
                    $AddParam = @{
                        Object = $Output
                        Name   = $Name
                        Value  = $Item -join ','
                    }
                    Add-Property @AddParam
                }
            }
        }
        function Get-PSObject ($Object, $Output, $Prefix) {
            foreach ($Item in ($Object.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })) {
                if ($Item.Value.PSObject.TypeNames -contains 'System.Object[]') {
                    # Add array members to output with 'prefix.name'
                    $ArrayParam = @{
                        Array  = $Item.Value
                        Output = $Output
                        Name   = if ($Prefix) {
                            "$($Prefix).$($Item.Name)"
                        } else {
                            $Item.Name
                        }
                    }
                    Get-Array @ArrayParam
                } elseif ($Item.Value.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                    # Add sub-objects to output with 'prefix.name'
                    $ObjectParam = @{
                        Object = $Item.Value
                        Output = $Output
                        Prefix = if ($Prefix) {
                            "$($Prefix).$($Item.Name)"
                        } else {
                            $Item.Name
                        }
                    }
                    Get-PSObject @ObjectParam
                } else {
                    # Add property to output with 'prefix.name'
                    $AddParam = @{
                        Object = $Output
                        Name   = if ($Prefix) {
                            "$($Prefix).$($Item.Name)"
                        } else {
                            $Item.Name
                        }
                        Value  = $Item.Value
                    }
                    Add-Property @AddParam
                }
            }
        }
        # Create output object
        $Output = [PSCustomObject] @{}
        
    }
    process {
        foreach ($Item in $PSBoundParameters.Object) {
            if ($Item.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                # Add sorted properties to output
                Get-PSObject -Object $Item -Output $Output
            } else {
                # Add strings to output as 'id'
                $AddParam = @{
                    Object = $Output
                    Name   = 'id'
                    Value  = $Item
                }
                Add-Property @AddParam
            }
        }
        if ($OutputPath) {
            # Output to CSV
            $Output | Export-Csv -Path $OutputPath -NoTypeInformation -Append
        } else {
            # Output to console
            $Output
        }
    }
    end {
        if ($OutputPath -and (Test-Path $OutputPath)) {
            Get-ChildItem $OutputPath
        }
    }
}
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
                ConvertTo-Json -InputObject @( $FileContent ) -Depth 16 | Out-File -FilePath $ItemFile -Append
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
function Find-FalconDuplicate {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [array] $Hosts,

        [Parameter(Position = 2)]
        [ValidateSet('external_ip', 'local_ip', 'mac_address', 'os_version', 'platform_name', 'serial_number')]
        [string] $Filter
    )
    begin {
        function Group-Selection ($Object, $GroupBy) {
            ($Object | Group-Object $GroupBy).Where({ $_.Count -gt 1 -and $_.Name }).foreach{
                $_.Group | Sort-Object last_seen | Select-Object -First ($_.Count - 1)
            }
        }
        # Comparison criteria and required properties for host results
        $Criteria = @('cid', 'hostname')
        $Required = @('cid', 'device_id', 'first_seen', 'last_seen', 'hostname')
        if ($PSBoundParameters.Filter) {
            $Criteria += $PSBoundParameters.Filter
            $Required += $PSBoundParameters.Filter
        }
        # Create filter for excluding results with empty $Criteria values
        $FilterScript = { (($Criteria).foreach{ "`$_.$($_)" }) -join ' -and ' }
    }
    process {
        $HostArray = if (!$PSBoundParameters.Hosts) {
            # Retreive Host details
            Get-FalconHost -Detailed -All
        } else {
            $PSBoundParameters.Hosts
        }
        ($Required).foreach{
            if (($HostArray | Get-Member -MemberType NoteProperty).Name -notcontains $_) {
                # Verify required properties are present
                throw "Missing required property '$_'."
            }
        }
        # Group, sort and output result
        $Param = @{
            Object  = $HostArray | Select-Object $Required | Where-Object -FilterScript $FilterScript
            GroupBy = $Criteria
        }
        $Output = Group-Selection @Param
    }
    end {
        if ($Output) {
            $Output
        } else {
            Write-Warning "No duplicates found."
        }
    }
}
function Get-FalconQueue {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [int] $Days
    )
    begin {
        $Days = if ($PSBoundParameters.Days) {
            $PSBoundParameters.Days
        } else {
            7
        }
        $OutputFile = Join-Path -Path (Get-Location).Path -ChildPath "FalconQueue_$(
            Get-Date -Format FileDateTime).csv"
        $Filter = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
    }
    process {
        try {
            Get-FalconSession -Filter $Filter -All -Verbose | ForEach-Object {
                Get-FalconSession -Ids $_ -Queue -Verbose | ForEach-Object {
                    foreach ($Session in $_) {
                        $Session.Commands | ForEach-Object {
                            $Object = [PSCustomObject] @{
                                aid                = $Session.aid
                                user_id            = $Session.user_id
                                user_uuid          = $Session.user_uuid
                                session_id         = $Session.id
                                session_created_at = $Session.created_at
                                session_deleted_at = $Session.deleted_at
                                session_updated_at = $Session.updated_at
                                session_status     = $Session.status
                                command_complete   = $false
                                command_stdout     = $null
                                command_stderr     = $null
                            }
                            $_.PSObject.Properties | ForEach-Object {
                                $Name = if ($_.Name -match '^(created_at|deleted_at|status|updated_at)$') {
                                    "command_$($_.Name)"
                                } else {
                                    $_.Name
                                }
                                $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $_.Value)))
                            }
                            if ($Object.command_status -eq 'FINISHED') {
                                $ConfirmCmd = Get-RtrCommand $Object.base_command -ConfirmCommand
                                $Param = @{
                                    CloudRequestId = $Object.cloud_request_id
                                    Verbose        = $true
                                    ErrorAction    = 'SilentlyContinue'
                                }
                                $CmdResult = & $ConfirmCmd @Param
                                if ($CmdResult) {
                                    ($CmdResult | Select-Object stdout, stderr, complete).PSObject.Properties |
                                    ForEach-Object {
                                        $Object."command_$($_.Name)" = $_.Value
                                    }
                                }
                            }
                            $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                        }
                    }
                }
            }
        } catch {
            throw $_
        } finally {
            if (Test-Path $OutputFile) {
                Get-ChildItem $OutputFile
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
                    'comment', 'description')
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
                $ConfigData.$Item.Import | ForEach-Object {
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
                        $Class.exceptions = $Class.exceptions | ForEach-Object {
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
            $ConfigData.$Item.$Type | Where-Object -FilterScript $FilterScript | ForEach-Object {
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
                [array] (Compare-ImportData $Item) | Select-Object name, group_type, description, assignment_rule |
                ForEach-Object {
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
                    $Policy.settings.variants | Where-Object { $_.build } | ForEach-Object {
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
        foreach ($Pair in $ConfigData.GetEnumerator().Where({ $_.Key -match '^(Ioc|(Ml|Sv)Exclusion)$' -and
        $_.Value.Import })) {
            # Create IOCs and exclusions if assigned to 'all' or can be assigned to Host Groups
            if ($Pair.Key -eq 'Ioc') {
                ($Pair.Value)['Created'] = Invoke-ConfigArray $Pair.Key
                if (($Pair.Value).Created) {
                    foreach ($Item in ($Pair.Value).Created) {
                        Write-Host "Created $($Pair.Key) '$($Item.type):$($Item.value)'."
                    }
                }
            } else {
                $ConfigData.($Pair.Key)['Created'] = foreach ($Import in $Pair.Value.Import) {
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
                            Invoke-ConfigItem @Param | ForEach-Object {
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
                            Invoke-ConfigItem @Param | ForEach-Object {
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
                                Invoke-ConfigItem @Param | ForEach-Object {
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
                            Invoke-ConfigItem @Param | ForEach-Object {
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
                        Invoke-ConfigItem @Param | ForEach-Object {
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
                $Pair.Value.Created | ForEach-Object {
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
function Invoke-FalconDeploy {
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        # Fields to collect from 'Put' files list
        $PutFields = @('id', 'name', 'created_timestamp', 'modified_timestamp', 'sha256')
        function Write-RtrResult ($Object, $Step, $BatchId) {
            # Create output, append results and output to CSV
            $Output = foreach ($Item in $Object) {
                [PSCustomObject] @{
                    aid              = $Item.aid
                    batch_id         = $BatchId
                    session_id       = $null
                    cloud_request_id = $null
                    deployment_step  = $Step
                    complete         = $false
                    offline_queued   = $false
                    errors           = $null
                    stderr           = $null
                    stdout           = $null
                }
            }
            Get-RtrResult -Object $Object -Output $Output | Export-Csv $OutputFile -Append -NoTypeInformation
        }
        # Set output file and executable details
        $OutputFile = Join-Path -Path (Get-Location).Path -ChildPath "FalconDeploy_$(
            Get-Date -Format FileDateTime).csv"
        $FilePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        [array] $HostArray = if ($PSBoundParameters.GroupId) {
            try {
                # Find Host Group member identifiers
                Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId
            } catch {
                throw $_
            }
        } else {
            # Use provided Host identifiers
            $PSBoundParameters.HostIds
        }
        if ($HostArray) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = Get-FalconPutFile -Filter "name:['$Filename']" -Detailed | Select-Object $PutFields |
                ForEach-Object {
                    [PSCustomObject] @{
                        id                 = $_.id
                        name               = $_.name
                        created_timestamp  = [datetime] $_.created_timestamp
                        modified_timestamp = [datetime] $_.modified_timestamp
                        sha256             = $_.sha256
                    }
                }
                $LocalFile = Get-ChildItem $FilePath | Select-Object CreationTime, Name, LastWriteTime |
                ForEach-Object {
                    [PSCustomObject] @{
                        name               = $_.Name
                        created_timestamp  = $_.CreationTime
                        modified_timestamp = $_.LastWriteTime
                        sha256             = ((Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash).ToLower()
                    }
                }
                if ($LocalFile -and $CloudFile) {
                    if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                        Write-Host "Matched hash values between local and cloud files..."
                    } else {
                        Write-Host "[CloudFile]"
                        $CloudFile | Select-Object name, created_timestamp, modified_timestamp, sha256 |
                            Format-List | Out-Host
                        Write-Host "[LocalFile]"
                        $LocalFile | Select-Object name, created_timestamp, modified_timestamp, sha256 |
                            Format-List | Out-Host
                        $FileChoice = $host.UI.PromptForChoice(
                            "'$Filename' exists in your 'Put' Files. Use existing version?", $null,
                            [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No"), 0)
                        if ($FileChoice -eq 0) {
                            Write-Host "Proceeding with CloudFile: $($CloudFile.id)..."
                        } else {
                            $RemovePut = Remove-FalconPutFile -Id $CloudFile.id
                            if ($RemovePut.writes.resources_affected -eq 1) {
                                Write-Host "Removed CloudFile: $($CloudFile.id)"
                            }
                        }
                    }
                }
            } catch {
                throw $_
            }
        }
    }
    process {
        if ($HostArray) {
            $AddPut = if ($RemovePut.writes.resources_affected -eq 1 -or !$CloudFile) {
                Write-Host "Uploading $Filename..."
                $Param = @{
                    Path        = $FilePath
                    Name        = $Filename
                    Description = "$ProcessName"
                    Comment     = 'PSFalcon: Invoke-FalconDeploy'
                }
                Send-FalconPutFile @Param
            }
            if ($AddPut.writes.resources_affected -ne 1 -and !$CloudFile.id) {
                throw "Upload failed."
            }
            try {
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                    $Param = @{
                        HostIds = $HostArray[$i..($i + 499)]
                    }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '(QueueOffline|Timeout)' { $Param[$_] = $PSBoundParameters.$_ }
                    }
                    $Session = Start-FalconSession @Param
                    $SessionHosts = if ($Session) {
                        # Output result to CSV and return list of successful 'session_start' hosts
                        Write-RtrResult -Object $Session.hosts -Step 'session_start' -BatchId $Session.batch_id
                        ($Session.hosts | Where-Object { $_.complete -eq $true -or
                            $_.offline_queued -eq $true }).aid
                    }
                    $PutHosts = if ($SessionHosts) {
                        # Invoke 'put' on successful hosts
                        Write-Host "Sending $Filename to $(($SessionHosts | Measure-Object).Count) host(s)..."
                        $Param = @{
                            BatchId         = $Session.batch_id
                            Command         = 'put'
                            Arguments       = "$Filename"
                            OptionalHostIds = $SessionHosts
                        }
                        if ($PSBoundParameters.Timeout) {
                            $Param['Timeout'] = $PSBoundParameters.Timeout
                        }
                        $CmdPut = Invoke-FalconAdminCommand @Param
                        if ($CmdPut) {
                            # Output result to CSV and return list of successful 'put_file' hosts
                            Write-RtrResult -Object $CmdPut -Step 'put_file' -BatchId $Session.batch_id
                            ($CmdPut | Where-Object { $_.stdout -eq 'Operation completed successfully.' -or
                                $_.offline_queued -eq $true }).aid
                        }
                    }
                    if ($PutHosts) {
                        # Invoke 'run'
                        Write-Host "Starting $Filename on $(($PutHosts | Measure-Object).Count) host(s)..."
                        $Arguments = "\$Filename"
                        if ($PSBoundParameters.Arguments) {
                            $Arguments += " -CommandLine=`"$($PSBoundParameters.Arguments)`""
                        }
                        $Param = @{
                            BatchId         = $Session.batch_id
                            Command         = 'run'
                            Arguments       = $Arguments
                            OptionalHostIds = $PutHosts
                        }
                        if ($PSBoundParameters.Timeout) {
                            $Param['Timeout'] = $PSBoundParameters.Timeout
                        }
                        $CmdRun = Invoke-FalconAdminCommand @Param
                        if ($CmdRun) {
                            # Output result to CSV
                            Write-RtrResult -Object $CmdRun -Step 'run_file' -BatchId $Session.batch_id
                        }
                    }
                }
            } catch {
                throw $_
            } finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile
                }
            }
        }
    }
}
function Invoke-FalconRtr {
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'get',
            'getsid', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir', 'mount', 'mv',
            'netstat', 'ps', 'put', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload', 'restart',
            'rm', 'run', 'runscript', 'shutdown', 'umount', 'unmap', 'update history', 'update install',
            'update list', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        function Initialize-Output ([array] $HostIds) {
            # Create initial array of output for each host
            ($HostIds).foreach{
                $Item = [PSCustomObject] @{
                    aid              = $_
                    batch_id         = $null
                    session_id       = $null
                    cloud_request_id = $null
                    complete         = $false
                    offline_queued   = $false
                    errors           = $null
                    stderr           = $null
                    stdout           = $null
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
                }
                if ($PSBoundParameters.GroupId) {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
                }
                $Item
            }
        }
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Command -eq 'runscript' -and
        $PSBoundParameters.Arguments -notmatch '-Timeout=\d{2,3}') {
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
        # Determine Real-time Response command to invoke
        $InvokeCmd = if ($PSBoundParameters.Command -eq 'get') {
            'Invoke-FalconBatchGet'
        } else {
            Get-RtrCommand $PSBoundParameters.Command
        }
    }
    process {
        [array] $HostArray = if ($PSBoundParameters.GroupId) {
            try {
                # Find Host Group member identifiers
                ,(Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId)
            } catch {
                throw $_
            }
        } else {
            # Use provided Host identifiers
            ,$PSBoundParameters.HostIds
        }
        try {
            for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                # Create baseline output and define request parameters
                [array] $Group = Initialize-Output $HostArray[$i..($i + 499)]
                $InitParam = @{
                    HostIds = $Group.aid
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InitParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                # Define command request parameters
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $CmdParam = @{
                        FilePath = $PSBoundParameters.Arguments
                    }
                } else {
                    $CmdParam = @{
                        Command = $PSBoundParameters.Command
                    }
                    if ($PSBoundParameters.Arguments) {
                        $CmdParam['Arguments'] = $PSBoundParameters.Arguments
                    }
                }
                if ($PSBoundParameters.Timeout) {
                    @($InitParam, $CmdParam).foreach{
                        $_['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                # Request session and capture initialization result
                $InitRequest = Start-FalconSession @InitParam
                $InitResult = Get-RtrResult -Object $InitRequest.hosts -Output $Group
                if ($InitRequest.batch_id) {
                    $InitResult | Where-Object { $_.session_id } | ForEach-Object {
                        # Add batch_id to initialized sessions
                        $_.batch_id = $InitRequest.batch_id
                    }
                    # Perform command request and capture result
                    $CmdRequest = & $InvokeCmd @CmdParam -BatchId $InitRequest.batch_id
                    $CmdResult = Get-RtrResult -Object $CmdRequest -Output $InitResult
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet' -and $CmdRequest.batch_get_cmd_req_id) {
                        $CmdResult | Where-Object { $_.session_id -and $_.complete -eq $true } | ForEach-Object {
                            # Add 'batch_get_cmd_req_id' and remove 'stdout' from session
                            $_.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id',
                                $CmdRequest.batch_get_cmd_req_id)))
                            $_.stdout = $null
                        }
                    }
                    $CmdResult
                } else {
                    $InitResult
                }
            }
        } catch {
            throw $_
        }
    }
}
function Send-FalconWebhook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('Slack')]
        [string] $Type,

        [Parameter(Mandatory = $true, Position = 2)]
        [System.Uri] $Path,

        [Parameter(Position = 3)]
        [string] $Label,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 4)]
        [object] $Object
    )
    begin {
        $Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Remove default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization
            [void] $Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
        }
    }
    process {
        [array] $Content = switch ($PSBoundParameters.Type) {
            'Slack' {
                # Create 'attachment' for each object in submission
                $Object | Export-FalconReport | ForEach-Object {
                    [array] $Fields = $_.PSObject.Properties | ForEach-Object {
                        ,@{
                            title = $_.Name
                            value = if ($_.Value -is [boolean]) {
                                # Convert [boolean] to [string]
                                if ($_.Value -eq $true) {
                                    'true'
                                } else {
                                    'false'
                                }
                            } else {
                                if ($null -eq $_.Value) {
                                    # Add [string] value when $null
                                    'null'
                                } else {
                                    $_.Value
                                }
                            }
                            short = $false
                        }
                    }
                    ,@{
                        username = "PSFalcon: $($Script:Falcon.ClientId)"
                        icon_url = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/icon.png'
                        text     = $PSBoundParameters.Label
                        attachments = @(
                            @{
                                fallback = 'Send-FalconWebhook'
                                fields   = $Fields
                            }
                        )
                    }
                }
            }
        }
        foreach ($Item in $Content) {
            try {
                $Param = @{
                    Path    = $PSBoundParameters.Path
                    Method  = 'post'
                    Headers = @{
                        ContentType = 'application/json'
                    }
                    Body = ConvertTo-Json -InputObject $Item -Depth 16
                }
                Write-Result ($Script:Falcon.Api.Invoke($Param))
            } catch {
                throw $_
            }
        }
    }
    end {
        if ($Token -and !$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Restore default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization', $Token)
        }
    }
}
function Show-FalconMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [array] $Indicators
    )
    begin {
        $FalconUI = "$($Script:Falcon.Hostname -replace 'api', 'falcon')"
        $Inputs = ($PSBoundParameters.Indicators).foreach{
            $Type = Confirm-String $_
            $Value = if ($Type -match '^(domain|md5|sha256)$') {
                $_.ToLower()
            } else {
                $_
            }
            if ($Type) {
                "$($Type):'$Value'"
            }
        }
    }
    process {
        Start-Process "$($FalconUI)/intelligence/graph?indicators=$($Inputs -join ',')"
    }
}
function Show-FalconModule {
    [CmdletBinding()]
    param()
    begin {
        $Parent = Split-Path -Path $Script:Falcon.Api.Path($PSScriptRoot) -Parent
    }
    process {
        if (Test-Path "$Parent\PSFalcon.psd1") {
            $Module = Import-PowerShellDataFile $Parent\PSFalcon.psd1
            [PSCustomObject] @{
                ModuleVersion    = "v$($Module.ModuleVersion) {$($Module.GUID)}"
                ModulePath       = $Parent
                UserHome         = $HOME
                UserPSModulePath = ($env:PSModulePath -split ';') -join ', '
                UserSystem       = ("PowerShell $($PSVersionTable.PSEdition): v$($PSVersionTable.PSVersion)" +
                    " [$($PSVersionTable.OS)]")
                UserAgent        = $Script:Falcon.Api.Client.DefaultRequestHeaders.UserAgent.ToString()
            }
        } else {
            throw "Cannot find 'PSFalcon.psd1'"
        }
    }
}