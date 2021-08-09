function Get-FalconQuickScan {
<#
.Synopsis
Search for QuickScan results
.Parameter Ids
QuickScan identifier(s)
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
quick-scan:read
#>
    [CmdletBinding(DefaultParameterSetName = '/scanner/queries/scans/v1:get')]
    param(
        [Parameter(ParameterSetName = '/scanner/entities/scans/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get')]
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
function Get-FalconQuickScanQuota {
<#
.Synopsis
Display your monthly Falcon QuickScan quota
.Role
quick-scan:read
#>
    [CmdletBinding()]
    param()
    begin {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/scanner/queries/scans/v1?limit=1"
            Method  = 'get'
            Headers = @{
                Accept = 'application/json'
            }
        }
    }
    process {
        $Request = $Script:Falcon.Api.Invoke($Param)
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta.quota
        } else {
            throw "Unable to retrieve QuickScan quota. Check client permissions."
        }
    }
}
function New-FalconQuickScan {
<#
.Synopsis
Submit a volume of files to Falcon QuickScan for a Machine-Learning judgement. Time required for analysis
increases with the number of samples in a volume but usually it should take less than 1 minute.
.Parameter Samples
Sha256 hash value(s)
.Role
quick-scan:write
#>
    [CmdletBinding(DefaultParameterSetName = '/scanner/entities/scans/v1:post')]
    param(
        [Parameter(ParameterSetName = '/scanner/entities/scans/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Samples
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('samples')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}