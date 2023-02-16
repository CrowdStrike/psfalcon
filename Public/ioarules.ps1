function Edit-FalconIoaGroup {
<#
.SYNOPSIS
Modify a custom Indicator of Attack rule group
.DESCRIPTION
All fields (plus 'rulegroup_version') are required when making a rule group change. PSFalcon adds missing values
automatically using data from your existing rule group.

Requires 'Custom IOA Rules: Write'.
.PARAMETER Name
Rule group name
.PARAMETER Enabled
Rule group enablement status
.PARAMETER Description
Rule group description
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconIoaGroup
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rule-groups/v1:patch',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Group',ParameterSetName='/ioarules/entities/rule-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:patch',ValueFromPipelineByPropertyName,
            Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [boolean]$Enabled,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Description,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:patch',ValueFromPipelineByPropertyName,
            Position=4)]
        [string]$Comment,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('RulegroupId')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('description','rulegroup_version','name','enabled','id','comment') }
            }
            Schema = 'api.RuleGroupV1'
        }
    }
    process {
        ($Param.Format.Body.root | Where-Object { $_ -ne 'id' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$PSBoundParameters.$_) {
                if (!$Existing) { $Existing = Get-FalconIoaGroup -Id $PSBoundParameters.Id -EA 0 }
                if ($Existing) {
                    $Value = if ($_ -eq 'rulegroup_version') { $Existing.version } else { $Existing.$_ }
                    $PSBoundParameters[$_] = $Value
                }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Edit-FalconIoaRule {
<#
.SYNOPSIS
Modify custom Indicator of Attack rules within a rule group
.DESCRIPTION
All fields are required (plus 'rulegroup_version') when making a rule group change. PSFalcon adds missing values
automatically using data from your existing rule group.

If an existing rule is submitted within 'rule_updates', it will be filtered to the required properties ('comment',
'description', 'disposition_id', 'enabled', 'field_values', 'instance_id', 'name', and 'pattern_severity')
including those under 'field_values' ('name', 'label', 'type' and 'values').

Requires 'Custom IOA Rules: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER RuleUpdate
An array of rule properties
.PARAMETER RulegroupId
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconIoaRule
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rules/v1:patch',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Rule',ParameterSetName='/ioarules/entities/rules/v1:patch')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:patch',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
           Position=2)]
        [Alias('rule_updates','rules','RuleUpdates')]
        [object[]]$RuleUpdate,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('rulegroup_id','id')]
        [string]$RulegroupId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('rulegroup_id','comment','rule_updates','rulegroup_version') }}
            Schema = 'Ioa.Rule'
        }
    }
    process {
        if ($RuleUpdate) {
            # Filter 'rule_updates' to required fields
            [object[]]$RuleRequired = 'instance_id','pattern_severity','enabled','disposition_id','name',
                'description','comment',@{ label = 'field_values'; expression = { $_.field_values |
                Select-Object name,label,type,values }}
            [object[]]$RuleUpdate = $RuleUpdate | Select-Object $RuleRequired
        }
        ($Param.Format.Body.root | Where-Object { $_ -ne 'rule_updates' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$PSBoundParameters.$_) {
                if (!$Existing) { $Existing = Get-FalconIoaGroup -Id $PSBoundParameters.RulegroupId -EA 0 }
                if ($Existing) {
                    $Value = if ($_ -eq 'rulegroup_version') { $Existing.version } else { $Existing.$_ }
                    $PSBoundParameters[$_] = $Value
                }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIoaGroup {
<#
.SYNOPSIS
Search for custom Indicator of Attack rule groups
.DESCRIPTION
Requires 'Custom IOA Rules: Read'.
.PARAMETER Id
Rule group identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaGroup
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/queries/rule-groups/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Group',ParameterSetName='/ioarules/entities/rule-groups/v1:get')]
    [OutputType([string],ParameterSetName='/ioarules/queries/rule-groups/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get',Position=1)]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get',Position=2)]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get',Position=3)]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get',Position=3)]
        [ValidateSet('created_by.asc','created_by.desc','created_on.asc','created_on.desc','description.asc',
            'description.desc','enabled.asc','enabled.desc','modified_by.asc','modified_by.desc',
            'modified_on.asc','modified_on.desc','name.asc','name.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get',Position=4)]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get')]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get')]
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups-full/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ioarules/queries/rule-groups/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','sort','q','offset','filter') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/ioarules/entities/rule-groups/v1:get' { 'api.RuleGroupV1' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        @(Invoke-Falcon @Param -Inputs $PSBoundParameters).foreach{
            if ($_.version -and $null -eq $_.version) { $_.version = 0 }
            $_
        }
    }
}
function Get-FalconIoaPlatform {
<#
.SYNOPSIS
Search for custom Indicator of Attack platforms
.DESCRIPTION
Requires 'Custom IOA Rules: Read'.
.PARAMETER Id
Platform
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaPlatform
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/queries/platforms/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Platform',ParameterSetName='/ioarules/entities/platforms/v1:get')]
    [OutputType([string],ParameterSetName='/ioarules/queries/platforms/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/platforms/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidateSet('windows','mac','linux',IgnoreCase=$false)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ioarules/queries/platforms/v1:get',Position=1)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioarules/queries/platforms/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ioarules/queries/platforms/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ioarules/queries/platforms/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ioarules/queries/platforms/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/ioarules/entities/platforms/v1:get' { 'domain.Platform' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIoaRule {
<#
.SYNOPSIS
Search for custom Indicator of Attack rules
.DESCRIPTION
Requires 'Custom IOA Rules: Read'.
.PARAMETER Id
Rule identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaRule
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/queries/rules/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Rule',ParameterSetName='/ioarules/entities/rules/GET/v1:post')]
    [OutputType([string],ParameterSetName='/ioarules/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rules/GET/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^\d+$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get',Position=3)]
        [ValidateSet('rules.created_by.asc','rules.created_by.desc','rules.created_on.asc',
            'rules.created_on.desc','rules.current_version.action_label.asc',
            'rules.current_version.action_label.desc','rules.current_version.description.asc',
            'rules.current_version.description.desc','rules.current_version.modified_by.asc',
            'rules.current_version.modified_by.desc','rules.current_version.modified_on.asc',
            'rules.current_version.modified_on.desc','rules.current_version.name.asc',
            'rules.current_version.name.desc','rules.current_version.pattern_severity.asc',
            'rules.current_version.pattern_severity.desc','rules.enabled.asc','rules.enabled.desc',
            'rules.ruletype_name.asc','rules.ruletype_name.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ioarules/queries/rules/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('limit','sort','q','offset','filter')
            }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/ioarules/entities/rules/GET/v1:post' { 'Ioa.Rule' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIoaSeverity {
<#
.SYNOPSIS
Search for custom Indicator of Attack severity levels
.DESCRIPTION
Requires 'Custom IOA Rules: Read'.
.PARAMETER Id
Severity identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaSeverity
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/queries/pattern-severities/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Severity',ParameterSetName='/ioarules/entities/pattern-severities/v1:get')]
    [OutputType([string],ParameterSetName='/ioarules/queries/pattern-severities/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/pattern-severities/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidateSet('critical','high','medium','low','informational',IgnoreCase=$false)]
        [Alias('Ids','pattern_severity')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ioarules/queries/pattern-severities/v1:get',Position=1)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioarules/queries/pattern-severities/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ioarules/queries/pattern-severities/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ioarules/queries/pattern-severities/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ioarules/queries/pattern-severities/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/ioarules/entities/pattern-severities/v1:get' { 'Ioa.Severity' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIoaType {
<#
.SYNOPSIS
Search for custom Indicator of Attack types
.DESCRIPTION
Requires 'Custom IOA Rules: Read'.
.PARAMETER Id
Type identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaType
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/queries/rule-types/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Type',ParameterSetName='/ioarules/entities/rule-types/v1:get')]
    [OutputType([string],ParameterSetName='/ioarules/queries/rule-types/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rule-types/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^\d{1,2}$')]
        [Alias('Ids','ruletype_id')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ioarules/queries/rule-types/v1:get',Position=1)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioarules/queries/rule-types/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ioarules/queries/rule-types/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ioarules/queries/rule-types/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ioarules/queries/rule-types/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/ioarules/entities/rule-types/v1:get' { 'Ioa.Type' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function New-FalconIoaGroup {
<#
.SYNOPSIS
Create a custom Indicator of Attack rule group
.DESCRIPTION
Requires 'Custom IOA Rules: Write'.
.PARAMETER Name
Rule group name
.PARAMETER Platform
Operating system platform
.PARAMETER Description
Rule group description
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconIoaGroup
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rule-groups/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Group',ParameterSetName='/ioarules/entities/rule-groups/v1:post')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('windows','mac','linux',IgnoreCase=$false)]
        [Alias('platform_name')]
        [string]$Platform,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Description,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [string]$Comment
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('description','platform','name','comment') }}
            Schema = 'api.RuleGroupV1'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function New-FalconIoaRule {
<#
.SYNOPSIS
Create a custom Indicator of Attack rule within a rule group
.DESCRIPTION
'RuleTypeId' and 'DispositionId' values can be found using 'Get-FalconIoaType -Detailed' under the 'id' and
'disposition_map' properties.

Requires 'Custom IOA Rules: Write'.
.PARAMETER Name
Rule name
.PARAMETER PatternSeverity
Rule severity
.PARAMETER RuletypeId
Rule type
.PARAMETER DispositionId
Disposition identifier [10: Monitor, 20: Detect, 30: Block]
.PARAMETER FieldValue
An array of rule properties
.PARAMETER Description
Rule description
.PARAMETER Comment
Audit log comment
.PARAMETER RulegroupId
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconIoaRule
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rules/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Rule',ParameterSetName='/ioarules/entities/rules/v1:post')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('critical','high','medium','low','informational',IgnoreCase=$false)]
        [Alias('pattern_severity')]
        [string]$PatternSeverity,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidateSet(1,2,5,6,9,10,11,12)]
        [Alias('ruletype_id')]
        [string]$RuletypeId,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [ValidateSet(10,20,30)]
        [Alias('disposition_id')]
        [int32]$DispositionId,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=5)]
        [Alias('field_values','FieldValues')]
        [object[]]$FieldValue,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',ValueFromPipelineByPropertyName,Position=6)]
        [string]$Description,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',ValueFromPipelineByPropertyName,Position=7)]
        [string]$Comment,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            Position=8)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('rulegroup_id','id')]
        [string]$RulegroupId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('rulegroup_id','disposition_id','comment','description','pattern_severity',
                        'ruletype_id','field_values','name')
                }
            }
            Schema = 'Ioa.Rule'
        }
    }
    process {
        if ($PSBoundParameters.FieldValue) {
            # Filter 'field_values' to required fields
            $PSBoundParameters.FieldValue = $PSBoundParameters.FieldValue | Select-Object name,label,type,values
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Remove-FalconIoaGroup {
<#
.SYNOPSIS
Remove custom Indicator of Attack rule groups
.DESCRIPTION
Requires 'Custom IOA Rules: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconIoaGroup
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rule-groups/v1:delete',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Meta.Response',ParameterSetName='/ioarules/entities/rule-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/ioarules/entities/rule-groups/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','comment') }
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Remove-FalconIoaRule {
<#
.SYNOPSIS
Remove custom Indicator of Attack rules from rule groups
.DESCRIPTION
Requires 'Custom IOA Rules: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER RuleGroupId
Rule group identifier
.PARAMETER Id
Rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconIoaRule
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rules/v1:delete',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Meta.Response',ParameterSetName='/ioarules/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('rule_group_id','rulegroup_id','ioa_rule_groups')]
        [string]$RuleGroupId,
        [Parameter(ParameterSetName='/ioarules/entities/rules/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidatePattern('^\d+$')]
        [Alias('Ids','rule_ids','instance_id')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','rule_group_id','comment') }
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Test-FalconIoaRule {
<#
.SYNOPSIS
Validate fields and patterns of a custom Indicator of Attack rule
.DESCRIPTION
Requires 'Custom IOA Rules: Write'.
.PARAMETER Field
An array of rule properties
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconIoaRule
#>
    [CmdletBinding(DefaultParameterSetName='/ioarules/entities/rules/validate/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Ioa.Rule.Test',ParameterSetName='/ioarules/entities/rules/validate/v1:post')]
    param(
        [Parameter(ParameterSetName='/ioarules/entities/rules/validate/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [Alias('fields','field_values')]
        [object[]]$Field
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('fields') }}
            Schema = 'Ioa.Rule.Test'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}