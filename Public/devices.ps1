function Add-FalconGroupingTag {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
        $PSBoundParameters['action'] = 'add'
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHost {
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/devices-scroll/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/v1:get', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/devices/login-history/v1:post', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/devices/network-address-history/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 5)]
        [ValidateSet('login_history', 'network_history')]
        [array] $Include,

        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Mandatory = $true)]
        [switch] $Hidden,
        
        [Parameter(ParameterSetName = '/devices/combined/devices/login-history/v1:post', Mandatory = $true)]
        [switch] $Login,

        [Parameter(ParameterSetName = '/devices/combined/devices/network-address-history/v1:post',
            Mandatory = $true)]
        [switch] $Network,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
        }
    }
    process {
        $Param['Format'] = if ($Param.Endpoint -match 'post$') {
            @{ Body = @{ root = @('ids') }}
        } else {
            @{ Query = @('ids', 'filter', 'sort', 'limit', 'offset') }
        }
        $Request = Invoke-Falcon @Param
        if ($PSBoundParameters.Include) {
            if (!$Request.device_id) {
                $Request = ($Request).foreach{
                    ,[PSCustomObject] @{ device_id = $_ }
                }
            }
            if ($PSBoundParameters.Include -contains 'login_history') {
                foreach ($Object in (& $MyInvocation.MyCommand.Name -Ids $Request.device_id -Login)) {
                    $AddParam = @{
                        Object = $Request | Where-Object { $_.device_id -eq $Object.device_id }
                        Name   = 'login_history'
                        Value  = $Object.recent_logins
                    }
                    Add-Property @AddParam
                }
            }
            if ($PSBoundParameters.Include -contains 'network_history') {
                foreach ($Object in (& $MyInvocation.MyCommand.Name -Ids $Request.device_id -Network)) {
                    $AddParam = @{
                        Object = $Request | Where-Object { $_.device_id -eq $Object.device_id }
                        Name   = 'network_history'
                        Value  = $Object.history
                    }
                    Add-Property @AddParam
                }
            }
        }
        $Request
    }
}
function Invoke-FalconHostAction {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices-actions/v2:post')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('contain', 'lift_containment', 'hide_host', 'unhide_host')]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Name = 'action_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root = @('ids')
                }
            }
        }
        $Param['Max'] = if ($Param.Inputs.action_name -match 'host$') {
            100
        } else {
            500
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconGroupingTag {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
        $PSBoundParameters['action'] = 'remove'
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}