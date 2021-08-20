function Edit-FalconDeviceControlPolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconDeviceControlPolicy'
                    Endpoint = '/policy/entities/device-control/v1:patch'
                    Required = @('id')
                    Pattern  = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/device-control/v1:patch'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'id', 'description', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicyMember {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'id', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconDeviceControlPolicyAction {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        $Fields = @{
            name = 'action_name'
        }
        $PSBoundParameters.Add('Ids', @( $PSBoundParameters.Id ))
        [void] $PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $PSBoundParameters.Add('action_parameters', @(
                @{
                    name  = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            ))
            [void] $PSBoundParameters.Remove('GroupId')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root = @('ids', 'action_parameters')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconDeviceControlPolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconDeviceControlPolicy'
                    Endpoint = '/policy/entities/device-control/v1:post'
                    Required = @('name', 'platform_name')
                    Content  = @('platform_name')
                    Format   = @{
                        platform_name = 'PlatformName'
                    }
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [string] $CloneId
    )
    begin {
        $Fields = @{
            Array        = 'resources'
            CloneId      = 'clone_id'
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/device-control/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'description', 'clone_id', 'platform_name', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconDeviceControlPolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:delete', Mandatory = $true,
            Position = 1)]
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
function Set-FalconDeviceControlPrecedence {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('platform_name', 'ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}