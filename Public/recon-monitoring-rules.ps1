function Edit-FalconReconAction {
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
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') {
                $true
            } else {
                throw "'$_' is not a valid email address."
            }
        })]
        [array] $Recipients,

        [Parameter(ParameterSetName = '/recon/entities/actions/v1:patch', Mandatory = $true, Position = 4)]
        [ValidateSet('enabled', 'muted')]
        [string] $Status

    )
    process {
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
        Invoke-Falcon @Param
    }
}
function Edit-FalconReconNotification {
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
    begin {
        $Fields = @{
            AssignedToUuid = 'assigned_to_uuid'
        }
    }
    process {
        if ($PSBoundParameters.Array) {
            if (!$Script:Falcon.Hostname) {
                Request-FalconToken
            }
            $Param = @{
                Path    = "$($Script:Falcon.Hostname)/recon/entities/notifications/v1"
                Method  = 'patch'
                Headers = @{
                    Accept      = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Edit notifications in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                if ($Script:Humio.Path -and $Script:Humio.Token -and $Script:Humio.Enabled) {
                    $Script:Falcon.Request['Body'] = $Param.Body
                }
                $ReqTime = Get-Date -Format o
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request -Time $ReqTime
            }
        } else {
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
        [ValidateScript({ Test-FqlStatement $_ })]
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
            if (!$Script:Falcon.Hostname) {
                Request-FalconToken
            }
            $Param = @{
                Path    = "$($Script:Falcon.Hostname)/recon/entities/rules/v1"
                Method  = 'patch'
                Headers = @{
                    Accept      = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Edit rules in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                if ($Script:Humio.Path -and $Script:Humio.Token -and $Script:Humio.Enabled) {
                    $Script:Falcon.Request['Body'] = $Param.Body
                }
                $ReqTime = Get-Date -Format o
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request -Time $ReqTime
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
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/actions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/actions/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconReconNotification {
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/notifications/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:get', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/recon/entities/notifications-detailed/v1:get', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/recon/entities/notifications-translated/v1:get', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/recon/entities/notifications-detailed-translated/v1:get',
            Mandatory = $true,Position = 1)]
        [ValidatePattern('^\w{76}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/notifications/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconReconRule {
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/rules/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/recon/queries/rules/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'q', 'sort', 'offset', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconReconRulePreview {
    [CmdletBinding(DefaultParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post')]
    param(
        [Parameter(ParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Topic,

        [Parameter(ParameterSetName = '/recon/aggregates/rules-preview/GET/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter
    )
    process {
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
        Invoke-Falcon @Param
    }
}
function New-FalconReconAction {
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
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') {
                $true
            } else {
                throw "'$_' is not a valid email address."
            }
        })]
        [array] $Recipients
    )
    begin {
        $Fields = @{
            RuleId = 'rule_id'
        }
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function New-FalconReconRule {
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
        [ValidateScript({ Test-FqlStatement $_ })]
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
            if (!$Script:Falcon.Hostname) {
                Request-FalconToken
            }
            $Param = @{
                Path    = "$($Script:Falcon.Hostname)/recon/entities/rules/v1"
                Method  = 'post'
                Headers = @{
                    Accept      = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Create rules in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @( $Group ) -Depth 8
                if ($Script:Humio.Path -and $Script:Humio.Token -and $Script:Humio.Enabled) {
                    $Script:Falcon.Request['Body'] = $Param.Body
                }
                $ReqTime = Get-Date -Format o
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request -Time $ReqTime
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
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/actions/v1:delete', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconReconRule {
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/rules/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconReconNotification {
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/notifications/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/recon/entities/notifications/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{76}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}