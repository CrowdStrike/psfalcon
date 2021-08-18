function Edit-FalconInstallToken {
<#
.Synopsis
Modify installation token(s)
.Description
Requires 'installation-tokens:write'.
.Parameter Ids
Installation token identifier(s)
.Parameter Label
Installation token label
.Parameter ExpiresTimestamp
Installation token expiration time (RFC-3339), or 'null'
.Parameter Revoked
Set revocation status of the installation token
.Role
installation-tokens:write
.Example
PS>Edit-FalconInstallToken -Ids <id>, <id> -Revoked $true

Revoke the installation tokens <id> and <id>.
.Example
PS>Edit-FalconInstallToken -Ids <id> -Label 'Token no expiration' -ExpiresTimeStamp null

Changes the label of installation token <id> to 'Token no expiration' and removes the existing expiration time,
meaning the token will never expire.
#>
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallToken {
<#
.Synopsis
Search for installation tokens
.Description
Requires 'installation-tokens:read'.
.Parameter Ids
Installation token identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
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
installation-tokens:read
.Example
PS>Get-FalconInstallToken -Detailed

Displays installation tokens and related information.
.Example
PS>Get-FalconInstallToken -Ids <id>

Displays information about the installation token <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,
        
        [Parameter(ParameterSetName = '/installation-tokens/queries/tokens/v1:get', Position = 2)]
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
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallTokenEvent {
<#
.Synopsis
Search for installation token audit events
.Description
Requires 'installation-tokens:read'.
.Parameter Ids
Installation token audit event identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
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
installation-tokens:read
.Example
PS>Get-FalconInstallTokenEvent -Detailed -All

Show all available installation token audit events with detail.
#>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/audit-events/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/installation-tokens/queries/audit-events/v1:get', Position = 1)]
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
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconInstallTokenSetting {
<#
.Synopsis
List current installation token settings
.Description
Requires 'installation-tokens:read'.

Returns the maximum number of allowed installation tokens, and whether or not they are required for installation
of the Falcon Sensor.
.Role
installation-tokens:read
#>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/customer-settings/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function New-FalconInstallToken {
<#
.Synopsis
Create an installation token
.Description
Requires 'installation-tokens:write'.
.Parameter Label
Installation token label
.Parameter ExpiresTimestamp
Installation token expiration time (RFC-3339), or 'null'
.Role
installation-tokens:write
.Example
PS>New-FalconInstallToken -Label 'My Token' -ExpiresTimestamp '2021-12-31T00:00:00Z'

Creates the installation token 'My Token', which expires on 2021-12-31 at 00:00:00 UTC.
#>
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconInstallToken {
<#
.Synopsis
Delete installation token(s)
.Description
Requires 'installation-tokens:write'.
.Parameter Ids
Installation token identifier(s)
.Role
installation-tokens:write
.Example
PS>Remove-FalconInstallToken -Ids <id>, <id>

Delete installation tokens <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/tokens/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/installation-tokens/entities/tokens/v1:delete', Mandatory = $true,
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