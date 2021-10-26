function Edit-FalconSensorUpdatePolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update/v2:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconSensorUpdatePolicy'
                    Endpoint = '/policy/entities/sensor-update/v2:patch'
                    Required = @('id')
                    Pattern  = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/sensor-update/v2:patch'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'id', 'description', 'settings')
                    root      = @('resources')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconBuild {
    [CmdletBinding(DefaultParameterSetName = '/policy/combined/sensor-update-builds/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-builds/v1:get')]
        [ValidateSet('linux', 'mac', 'windows')]
        [string] $Platform
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('platform')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconSensorUpdatePolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/sensor-update/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('created_by','created_timestamp','description','enabled','groups',
            'modified_by','modified_timestamp','name','name.raw','platform_name')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get')]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconSensorUpdatePolicyMember {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'id', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconUninstallToken {
    [CmdletBinding(DefaultParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post', Mandatory = $true,
            ValueFromPipeline = $true, Position = 1)]
        [Alias('device_id')]
        [ValidatePattern('^(\w{32}|MAINTENANCE)$')]
        [string] $DeviceId,

        [Parameter(ParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post', Position = 2)]
        [string] $AuditMessage
    )
    begin {
        $Fields = @{
            DeviceId     = 'device_id'
            AuditMessage = 'audit_message'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('audit_message', 'device_id')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Invoke-FalconSensorUpdatePolicyAction {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        $Fields = @{
            name = 'action_name'
        }
    }
    process {
        $PSBoundParameters['Ids'] = @( $PSBoundParameters.Id )
        [void] $PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $PSBoundParameters['action_parameters'] = @(
                @{
                    name  = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            )
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
        Invoke-Falcon @Param
    }
}
function New-FalconSensorUpdatePolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update/v2:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconSensorUpdatePolicy'
                    Endpoint = '/policy/entities/sensor-update/v2:post'
                    Required = @('name','platform_name')
                    Content  = @('platform_name')
                    Format   = @{
                        platform_name = 'PlatformName'
                    }
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Mandatory = $true, Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array        = 'resources'
            PlatformName = 'platform_name'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/sensor-update/v2:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('description', 'platform_name', 'name', 'settings')
                    root =      @('resources')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconSensorUpdatePolicy {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
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
function Set-FalconSensorUpdatePrecedence {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update-precedence/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-precedence/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            PlatformName = 'platform_name'
        }
    }
    process {
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
        Invoke-Falcon @Param
    }
}