function Edit-FalconIoaGroup {
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