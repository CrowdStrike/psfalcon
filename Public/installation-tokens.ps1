function Edit-FalconInstallToken {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/tokens/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:patch', Position = 2)]
        [string] $Label,

        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:patch', Position = 3)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|null)$')]
        [string] $ExpiresTimestamp,

        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:patch', Position = 4)]
        [boolean] $Revoked
    )
    begin {
        $Fields = @{
            ExpiresTimestamp = 'expires_timestamp'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids')
                Body  = @{
                    root = @('label', 'revoked', 'expires_timestamp')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallToken {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,
        
        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get', Position = 2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get', Position = 4)]
        [ValidateRange(1,1000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallTokenEvent {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/audit-events/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get', Position = 3)]
        [int] $Limit,
        
        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallTokenSetting {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/customer-settings/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function New-FalconInstallToken {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/tokens/v1:post')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Label,

        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|null)$')]
        [string] $ExpiresTimestamp
    )
    begin {
        $Fields = @{
            ExpiresTimestamp = 'expires_timestamp'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('label', 'expires_timestamp')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconInstallToken {
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/tokens/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:delete', Mandatory = $true,
            Position = 1)]
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