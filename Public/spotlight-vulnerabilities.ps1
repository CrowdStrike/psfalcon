function Get-FalconRemediation {
<#
.Synopsis
Retrieve remediation detail
.Parameter Ids
Remediation identifier(s)
.Role
spotlight-vulnerabilities:read
.Example
PS>Get-FalconRemediation -Ids <id>, <id>

List detailed information about remediations <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/spotlight/entities/remediations/v2:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/remediations/v2:get', Mandatory = $true,
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
function Get-FalconVulnerability {
<#
.Synopsis
Search for vulnerabilities
.Parameter Ids
Vulnerability identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter After
Pagination token to retrieve the next set of results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
spotlight-vulnerabilities:read
.Example
PS>Get-FalconVulnerability -Filter "created_timestamp:>'last 7 days'" -Detailed -All

Search for all vulnerabilities opened within the last 7 days and display detailed information.
.Example
PS>Get-FalconVulnerability -Ids <id>, <id>

List detailed information about vulnerabilities <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/vulnerabilities/v2:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Mandatory = $true,
            Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 3)]
        [ValidateRange(1, 400)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 4)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 5)]
        [string] $After,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('after', 'sort', 'ids', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}