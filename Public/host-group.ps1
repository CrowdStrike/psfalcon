function Edit-FalconHostGroup {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 4)]
        [string] $AssignmentRule
    )
    begin {
        $Fields = @{
            AssignmentRule = 'assignment_rule'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('assignment_rule', 'id', 'name', 'description')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHostGroup {
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'group_type.asc', 'group_type.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 3)]
        [ValidateRange(1, 500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'filter', 'sort', 'limit', 'offset')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHostGroupMember {
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 4)]
        [ValidateRange(1, 500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id', 'filter', 'sort', 'limit', 'offset')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconHostGroupAction {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-group-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-group-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-hosts', 'remove-hosts')]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/host-group-actions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/devices/entities/host-group-actions/v1:post', Mandatory = $true,
            Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds
    )
    begin {
        $Param = @{
            Path    = ("$($Script:Falcon.Hostname)/devices/entities/host-group-actions/v1?" + 
                "action_name=$($PSBoundParameters.Name)")
            Method  = 'post'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
        }
        $Body = @{
            action_parameters = @{
                name  = 'filter'
                value = ''
            }
            ids = @( $PSBoundParameters.Id )
        }
        $Max = 500
    }
    process {
        for ($i = 0; $i -lt ($PSBoundParameters.HostIds | Measure-Object).Count; $i += $Max) {
            $Clone = $Param.Clone()
            $Clone.Add('Body', $Body.Clone())
            $IdString = ($PSBoundParameters.HostIds[$i..($i + ($Max - 1))] | ForEach-Object {
                "'$_'"
            }) -join ','
            $Clone.Body.action_parameters.value = "(device_id:[$IdString])"
            Write-Result ($Script:Falcon.Api.Invoke($Clone))
        }
    }
}
function New-FalconHostGroup {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconHostGroup'
                    Endpoint = '/devices/entities/host-groups/v1:post'
                    Required = @('group_type', 'name')
                    Content  = @('group_type')
                    Format   = @{
                        group_type = 'GroupType'
                    }
                }
                Confirm-Parameter @Param
                if ($Object.group_type -eq 'static' -and $Object.assignment_rule) {
                    $ObjectString = ConvertTo-Json -InputObject $Object -Compress
                    throw "'assignment_rule' can only be used with 'group_type = dynamic'. $ObjectString"
                }
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('static', 'dynamic')]
        [string] $GroupType,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:post', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:post', Position = 4)]
        [ValidateScript({
            if ($PSBoundParameters.GroupType -eq 'static') {
                throw "'AssignmentRule' can only be used with GroupType 'dynamic'."
            } else {
                $true
            }
        })]
        [string] $AssignmentRule
    )
    begin {
        $Fields = @{
            Array          = 'resources'
            AssignmentRule = 'assignment_rule'
            GroupType      = 'group_type'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/devices/entities/host-groups/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'description', 'group_type', 'assignment_rule')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconHostGroup {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
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