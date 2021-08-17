function Edit-FalconReconAction {
<#
.Synopsis
Update an action for a Recon monitoring rule
.Parameter Id
Recon rule action identifier
.Parameter Frequency
Recon rule action frequency
.Parameter Recipients
One or more email addresses
.Parameter Status
Recon rule action status
.Role
recon-monitoring-rules:write
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:patch', Mandatory = $true, Position = 2)]
        [ValidateSet('asap', 'daily', 'weekly')]
        [string] $Frequency,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:patch', Mandatory = $true, Position = 3)]
        [array] $Recipients,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:patch', Mandatory = $true, Position = 4)]
        [ValidateSet('enabled', 'muted')]
        [string] $Status

    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('recipients', 'id', 'status', 'frequency')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconReconNotification {
<#
.Synopsis
Update Recon notification status or assignee
.Parameter Array
An array of Recon notifications to modify in a single request
.Parameter Id
Recon notification identifier
.Parameter AssignedToUuid
User identifier for assignment
.Parameter Status
Recon notification status
.Role
recon-monitoring-rules:write
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/notifications/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconReconNotification'
                    Endpoint = '/recon/entities/notifications/v1:patch'
                    Required = @('id', 'assigned_to_uuid', 'status')
                    Pattern  = @('id', 'assigned_to_uuid')
                    Format   = @{
                        assigned_to_uuid = 'AssignedToUuid'
                    }
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{76}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $AssignedToUuid,

        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:patch', Mandatory = $true, Position = 3)]
        [string] $Status
    )
    process {
        if ($PSBoundParameters.Array) {
            # Edit notifications in batches of 500
            $Param = @{
                Path    = '/recon/entities/notifications/v1'
                Method  = 'patch'
                Headers = @{
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                Write-Result ($Script:Falcon.Api.Invoke($Param))
            }
        } else {
            $Fields = @{
                AssignedToUuid = 'assigned_to_uuid'
            }
            $Param = @{
                Command  = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
                Format   = @{
                    Body = @{
                        root = @('assigned_to_uuid', 'id', 'status')
                    }
                }
            }
            Invoke-Falcon @Param
        }
    }
}
function Edit-FalconReconRule {
<#
.Synopsis
Update Recon monitoring rules
.Parameter Array
An array of Recon rules to modify in a single request
.Parameter Id
Recon monitoring rule identifier
.Parameter Name
Recon monitoring rule name
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Priority
Recon monitoring rule priority
.Parameter Permissions
Permission level [public: 'All Intel users', private: 'Recon Admins']
.Role
recon-monitoring-rules:write
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconReconRule'
                    Endpoint = '/recon/entities/rules/v1:patch'
                    Required = @('id', 'name', 'filter', 'priority', 'permissions')
                    Content  = @('permissions', 'priority')
                    Pattern  = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:patch', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:patch', Mandatory = $true, Position = 3)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:patch', Mandatory = $true, Position = 4)]
        [ValidateSet('high', 'medium', 'low')]
        [string] $Priority,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:patch', Mandatory = $true, Position = 5)]
        [ValidateSet('private', 'public')]
        [string] $Permissions
    )
    process {
        if ($PSBoundParameters.Array) {
            # Edit rules in batches of 500
            $Param = @{
                Path    = '/recon/entities/rules/v1'
                Method  = 'patch'
                Headers = @{
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                Write-Result ($Script:Falcon.Api.Invoke($Param))
            }
        } else {
            $Param = @{
                Command  = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Inputs   = $PSBoundParameters
                Format   = @{
                    Body = @{
                        root = @('permissions', 'priority', 'name', 'id', 'filter')
                    }
                }
            }
            Invoke-Falcon @Param
        }
    }
}
function Get-FalconReconAction {
<#
.Synopsis
Search for Recon actions
.Parameter Ids
One or more Recon action identifiers
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
recon-monitoring-rules:read
.Example
PS>Get-FalconReconAction -Detailed

Return the first set of detailed Recon action results.
.Example
PS>Get-FalconReconAction -Ids <id>, <id>

Retrieve detailed information about Recon actions <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/actions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 4)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get')]
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
        Invoke-Falcon @Param
    }
}
function Get-FalconReconNotification {
<#
.Synopsis
Search for Recon notifications
.Parameter Ids
One or more Recon action identifiers
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
.Parameter Intel
Include raw intelligence content
.Parameter Translate
Translate to English
.Parameter Combined
Include raw intelligence content and translate to English
.Role
recon-monitoring-rules:read
.Example
PS>Get-FalconReconNotification -Detailed

Return the first set of detailed Recon notification results.
.Example
PS>Get-FalconReconNotification -Ids <id>, <id>

Retrieve detailed information about Recon notifications <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/notifications/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{76}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 3)]
        [ValidateSet('created_date|asc', 'created_date|desc', 'updated_date|asc', 'updated_date|desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get')]
        [switch] $Total,

        [Parameter(ParameterSetName = '/recon/entities/notifications-detailed/v1:get', Mandatory = $true)]
        [switch] $Intel,

        [Parameter(ParameterSetName = '/recon/entities/notifications-translated/v1:get', Mandatory = $true)]
        [switch] $Translate,

        [Parameter(ParameterSetName = '/recon/entities/notifications-detailed-translated/v1:get',
            Mandatory = $true)]
        [switch] $Combined
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
        Invoke-Falcon @Param
    }
}
function Get-FalconReconRule {
<#
.Synopsis
Search for Recon monitoring rules
.Parameter Ids
One or more Recon monitoring rule identifiers
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
recon-monitoring-rules:read
.Example
PS>Get-FalconReconRule -Detailed

Return the first set of detailed Recon monitoring rule results.
.Example
PS>Get-FalconReconRule -Ids <id>, <id>

Retrieve detailed information about Recon monitoring rules <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/rules/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 3)]
        [ValidateSet('created_timestamp|asc', 'created_timestamp|desc', 'last_updated_timestamp|asc',
            'last_updated_timestamp|desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get')]
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
                Query = @('limit', 'ids', 'q', 'sort', 'offset', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconReconRulePreview {
<#
.Synopsis
Preview Recon monitoring rule notification count and distribution
.Parameter Filter
Recon monitoring rule filter
.Parameter Topic
Recon monitoring rule topic
.Role
recon-monitoring-rules:read
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post')]
    param(
        [Parameter(ParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post', Mandatory = $true,
            Position = 2)]
        [string] $Topic
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('filter', 'topic')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconReconAction {
<#
.Synopsis
Create actions for an existing Recon monitoring rule
.Parameter RuleId
Recon monitoring rule identifier
.Parameter Type
Recon monitoring rule notification type
.Parameter Frequency
Recon monitoring rule notification frequency
.Parameter Recipients
Recon monitoring rule notification recipients
.Role
recon-monitoring-rules:write
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $RuleId,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:post', Mandatory = $true, Position = 2)]
        [ValidateSet('email')]
        [string] $Type,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:post', Mandatory = $true, Position = 3)]
        [ValidateSet('asap', 'daily', 'weekly')]
        [string] $Frequency,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:post', Mandatory = $true, Position = 4)]
        [array] $Recipients
    )
    begin {
        $Fields = @{
            RuleId = 'rule_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root    = @('rule_id')
                    actions = @('recipients', 'type', 'frequency')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconReconRule {
<#
.Synopsis
Create Recon monitoring rules
.Parameter Array
An array of Recon rules to create in a single request
.Parameter Name
Recon monitoring rule name
.Parameter Topic
Recon monitoring rule topic
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Priority
Recon monitoring rule priority
.Parameter Permissions
Permission level [public: 'All Intel users', private: 'Recon Admins']
.Role
recon-monitoring-rules:write
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconReconRule'
                    Endpoint = '/recon/entities/rules/v1:post'
                    Required = @('name', 'topic', 'filter', 'priority', 'permissions')
                    Content  = @('permissions', 'priority', 'topic')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:post', Mandatory = $true, Position = 2)]
        [ValidateSet('SA_ALIAS', 'SA_AUTHOR', 'SA_BIN', 'SA_BRAND_PRODUCT', 'SA_CUSTOM', 'SA_CVE', 'SA_DOMAIN',
            'SA_EMAIL', 'SA_IP', 'SA_THIRD_PARTY', 'SA_VIP')]
        [string] $Topic,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:post', Mandatory = $true, Position = 3)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:post', Mandatory = $true, Position = 4)]
        [ValidateSet('high', 'medium', 'low')]
        [string] $Priority,

        [Parameter(ParameterSetName = '/recon/entities/rules/v1:post', Mandatory = $true, Position = 5)]
        [ValidateSet('private', 'public')]
        [string] $Permissions
    )
    process {
        if ($PSBoundParameters.Array) {
            # Create rules in batches of 500
            $Param = @{
                Path    = '/recon/entities/rules/v1'
                Method  = 'post'
                Headers = @{
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                Write-Result ($Script:Falcon.Api.Invoke($Param))
            }
        } else {
            $Param = @{
                Command  = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Inputs   = $PSBoundParameters
                Format   = @{
                    Body = @{
                        root = @('permissions', 'priority', 'name', 'filter', 'topic')
                     }
                }
            }
            Invoke-Falcon @Param
        }
    }
}
function Remove-FalconReconAction {
<#
.Synopsis
Delete an action from a Recon monitoring rule
.Parameter Id
Recon action identifier
.Role
recon-monitoring-rules:write
.Example
PS>Remove-FalconReconAction -Id <id>

Delete Recon action <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:delete', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconReconRule {
<#
.Synopsis
Delete Recon monitoring rules
.Parameter Ids
Recon monitoring rule identifier(s)
.Role
recon-monitoring-rules:write
.Example
PS>Remove-FalconReconRule -Ids <id>, <id>

Delete Recon monitoring rules <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/rules/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconNotification {
<#
.Synopsis
Delete Recon notifications. Notifications cannot be recovered after they are deleted.
.Parameter Ids
One or more Recon notification identifiers
.Role
recon-monitoring-rules:write
.Example
PS>Remove-FalconNotification -Ids <id>, <id>

Delete Recon notifications <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/notifications/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{76}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}