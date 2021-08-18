function Edit-FalconIoaGroup {
<#
.Synopsis
Modify a Custom IOA rule group
.Description
Requires 'custom-ioa:write'.

All fields (plus 'rulegroup_version') are required when making a Custom IOA rule group change. PSFalcon adds
missing values automatically using data from your existing rule group.
.Parameter Id
Custom IOA rule group identifier
.Parameter Name
Custom IOA rule group name
.Parameter Enabled
Custom IOA rule group status
.Parameter Description
Custom IOA rule group description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>Edit-FalconIoaGroup -Id <id> -Name updatedRuleGroup -enabled $true -Description 'My updated mac rule group'

Change the name of Custom IOA rule group <id> to 'updatedRuleGroup', description to 'My updated mac rule group',
and set 'enabled' to '$true'.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Position = 3)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Position = 4)]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Position = 5)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('description', 'rulegroup_version', 'name', 'enabled', 'id', 'comment')
                }
            }
        }
        ($Param.Format.Body.root | Where-Object { $_ -ne 'id' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$Param.Inputs.$_) {
                if (!$Existing) {
                    $Existing = Get-FalconIoaGroup -Ids $Param.Inputs.id -ErrorAction 'SilentlyContinue'
                }
                if ($Existing) {
                    $Value = if ($_ -eq 'rulegroup_version') {
                        $Existing.version
                    } else {
                        $Existing.$_
                    }
                    $PSBoundParameters.Add($_,$Value)
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconIoaRule {
<#
.Synopsis
Modify custom IOA rules within an IOA rule group
.Description
Requires 'custom-ioa:write'.

All fields are required (plus 'rulegroup_version') when making a Custom IOA rule group change. PSFalcon adds
missing values automatically using data from your existing rule group.

If an existing rule is submitted within 'rule_updates', it will be filtered to the required properties
('comment', 'description', 'disposition_id', 'enabled', 'field_values', 'instance_id', 'name', and 
'pattern_severity') including those under 'field_values' ('name', 'label', 'type' and 'values').
.Parameter RulegroupId
Custom IOA rule group identifier
.Parameter RuleUpdates
An array of custom IOA rule properties
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>$Group = Get-FalconIoaGroup -Ids <id>
PS>$Rule = $Group.rules | Where-Object { $_.name -eq 'BugRule' }
PS>$Rule.enabled = $true
PS>($Rule.field_values | Where-Object {
    $_.name -eq 'GrandparentImageFilename' }).values[0].value = '.+updatebug.exe'
PS>Edit-FalconIoaRule -RulegroupId $Group.id -RuleUpdates $Rule

Capture the existing Custom IOA rule group data as '$Group', then save the rule to update as '$Rule'. Change
'enabled' to '$true', and set the 'GrandParentImageFilename' value as '.+updatebug.exe', then submit it as a change
within the existing Custom IOA rule group.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RulegroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Position = 2)]
        [array] $RuleUpdates,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Position = 3)]
        [string] $Comment
    )
    begin {
        if ($PSBoundParameters.RuleUpdates) {
            # Filter 'rule_updates' to required fields
            $RuleRequired = @('instance_id', 'pattern_severity', 'enabled', 'disposition_id', 'name',
                'description', 'comment', 'field_values')
            $FieldRequired = @('name', 'label', 'type', 'values')
            [array] $PSBoundParameters.RuleUpdates = ,($PSBoundParameters.RuleUpdates |
                Select-Object $RuleRequired | ForEach-Object {
                    $_.field_values = $_.field_values | Select-Object $FieldRequired
                    $_
                }
            )
        }
        $Fields = @{
            RuleGroupId = 'rulegroup_id'
            RuleUpdates = 'rule_updates'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('rulegroup_id', 'comment', 'rule_updates', 'rulegroup_version')
                }
            }
        }
        ($Param.Format.Body.root | Where-Object { $_ -ne 'rule_updates' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$Param.Inputs.$_) {
                if (!$Existing) {
                    $Existing = Get-FalconIoaGroup -Ids $Param.Inputs.rulegroup_id -ErrorAction 'SilentlyContinue'
                }
                if ($Existing) {
                    $Value = if ($_ -eq 'rulegroup_version') {
                        $Existing.version
                    } else {
                        $Existing.$_
                    }
                    $PSBoundParameters.Add($_,$Value)
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaGroup {
<#
.Synopsis
Search for Custom IOA rule groups
.Description
Requires 'custom-ioa:read'.
.Parameter Ids
Custom IOA rule group identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
custom-ioa:read
.Example
PS>Get-FalconIoaGroup -Filter "name:'newRuleGroup'" -Detailed

Retrieve detailed results for the Custom IOA rule group named 'newRuleGroup'.
.Example
PS>Get-FalconIoaGroup -Ids <id>, <id>

Retrieve detailed results for Custom IOA rule groups <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 3)]
        [ValidateSet('created_by', 'created_on', 'description', 'enabled', 'modified_by', 'modified_on', 'name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param | ForEach-Object {
            if ($_.version -and $null -eq $_.version) {
                $_.version = 0
            }
            $_
        }
    }
}
function Get-FalconIoaPlatform {
<#
.Synopsis
List Custom IOA platforms
.Description
Requires 'custom-ioa:read'.
.Parameter Ids
Custom IOA platform(s)
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
custom-ioa:read
.Example
PS>Get-FalconIoaPlatform -Detailed

Retrieve the first set of detailed Custom IOA platform results.
.Example
PS>Get-FalconIoaPlatform -Ids <id>, <id>

Retrieve detailed results for Custom IOA platforms <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/platforms/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/platforms/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('windows', 'mac', 'linux')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get', Position = 2)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get', Position = 3)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaRule {
<#
.Synopsis
Search for Custom IOA rules
.Description
Requires 'custom-ioa:read'.
.Parameter Ids
Custom IOA rule identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
custom-ioa:read
.Example
PS>Get-FalconIoaRule -Detailed

Retrieve the first set of detailed Custom IOA rule results.
.Example
PS>Get-FalconIoaRule -Ids <id>, <id>

Retrieve detailed results for Custom IOA rules <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/GET/v1:post', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 3)]
        [ValidateSet('rules.created_by', 'rules.created_on', 'rules.current_version.action_label',
            'rules.current_version.description', 'rules.current_version.modified_by',
            'rules.current_version.modified_on', 'rules.current_version.name',
            'rules.current_version.pattern_severity', 'rules.enabled', 'rules.ruletype_name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'sort', 'q', 'offset', 'filter')
                Body  = @{
                    root = @('ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaSeverity {
<#
.Synopsis
List Custom IOA severity levels
.Description
Requires 'custom-ioa:read'.
.Parameter Ids
Custom IOA severities
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
custom-ioa:read
.Example
PS>Get-FalconIoaSeverity -Detailed

Retrieve the first set of detailed Custom IOA severity results.
.Example
PS>Get-FalconIoaSeverity -Ids <id>, <id>

Retrieve detailed results for Custom IOA severities <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/pattern-severities/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^(critical|high|medium|low|informational)$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get', Position = 1)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get', Position = 2)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaType {
<#
.Synopsis
List Custom IOA types
.Description
Requires 'custom-ioa:read'.
.Parameter Ids
Custom IOA types
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
custom-ioa:read
.Example
PS>Get-FalconIoaType -Detailed

Retrieve the first set of detailed Custom IOA type results.
.Example
PS>Get-FalconIoaType -Ids <id>, <id>

Retrieve detailed results for Custom IOA types <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-types/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-types/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{1,2}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get', Position = 2)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get', Position = 3)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoaGroup {
<#
.Synopsis
Create a Custom IOA rule group
.Description
Requires 'custom-ioa:write'.
.Parameter Platform
Operating System platform
.Parameter Name
Custom IOA rule group name
.Parameter Description
Custom IOA rule group description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>New-FalconIoaGroup -Platform mac -Name newRuleGroup -Description 'My new mac rule group'

Create a new Custom IOA rule group named 'newRuleGroup' with the description 'My new mac rule group'.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('windows', 'mac', 'linux')]
        [string] $Platform,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Position = 4)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('description', 'platform', 'name', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoaRule {
<#
.Synopsis
Create a Custom IOA rule within a rule group
.Description
Requires 'custom-ioa:write'.

'RuleTypeId' and 'DispositionId' values can be found using 'Get-FalconIoaType -Detailed' under the 'id' and
'disposition_map' properties.
.Parameter RulegroupId
Custom IOA rule group identifier
.Parameter Name
Custom IOA rule name
.Parameter PatternSeverity
Custom IOA rule severity
.Parameter RuletypeId
Custom IOA rule type
.Parameter DispositionId
Disposition identifier (10: Monitor, 20: Detect, 30: Block)
.Parameter FieldValues
An array of Custom IOA rule properties
.Parameter Description
Custom IOA rule description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>$FieldValues = @{ name = 'GrandparentImageFilename'; type = 'excludable'; values = @(@{ label = 'include';
    value = '.+bug.exe' })}
PS>New-FalconIoaRule -RulegroupId <id> -Name BugRule -PatternSeverity critical -RuletypeId 5 -DispositionId 30
-FieldValues $FieldValues

Create Custom IOA rule 'BugRule' within rule group <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RulegroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 3)]
        [ValidateSet('critical', 'high', 'medium', 'low', 'informational')]
        [string] $PatternSeverity,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 4)]
        [ValidateSet(1, 2, 5, 6, 9, 10, 11, 12)]
        [string] $RuletypeId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 5)]
        [ValidateSet(10, 20, 30)]
        [int32] $DispositionId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 6)]
        [array] $FieldValues,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post')]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post')]
        [string] $Comment
    )
    begin {
        $Fields = @{
            DispositionId   = 'disposition_id'
            FieldValues     = 'field_values'
            PatternSeverity = 'pattern_severity'
            RulegroupId     = 'rulegroup_id'
            RuletypeId      = 'ruletype_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('rulegroup_id', 'disposition_id', 'comment', 'description', 'pattern_severity',
                        'ruletype_id', 'field_values', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoaGroup {
<#
.Synopsis
Delete Custom IOA rule groups
.Description
Requires 'custom-ioa:write'.
.Parameter Ids
Custom IOA rule group identifier(s)
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>Remove-FalconIoaGroup -Ids <id>, <id>

Delete Custom IOA rule groups <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:delete', Position = 2)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoaRule {
<#
.Synopsis
Remove Custom IOA rules from rule groups
.Description
Requires 'custom-ioa:write'.
.Parameter RuleGroupId
Custom IOA rule group identifier
.Parameter Ids
Custom IOA rule identifier(s)
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
.Example
PS>Remove-FalconIoaRule -RuleGroupId <group_id> -Ids <id>, <id>

Delete Custom IOA rules <id> and <id> from rule group <group_id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RuleGroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete', Mandatory = $true, Position = 2)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete')]
        [string] $Comment
    )
    begin {
        $Fields = @{
            RuleGroupId = 'rule_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'rule_group_id', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Test-FalconIoaRule {
<#
.Synopsis
Validate fields and patterns of a Custom IOA rule
.Description
Requires 'custom-ioa:write'.
.Parameter Fields
An array of Custom IOA Rule properties
.Role
custom-ioa:write
.Example
PS>$Fields = @{ name = 'GrandparentImageFilename'; type = 'excludable'; values = @(@{ label = 'include';
    value = '.+bug.exe' })}
PS>Test-FalconIoaRule -Fields $Fields

Validate '$Fields', containing custom IOA rule properties.
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/validate/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/validate/v1:post', Mandatory = $true,
            Position = 1)]
        [array] $Fields
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('fields')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}