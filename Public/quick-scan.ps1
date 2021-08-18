function Get-FalconQuickScan {
<#
.Synopsis
Search for QuickScan results
.Description
Requires 'quick-scan:read'.
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
.Example
PS>Get-FalconQuickScan -Filter "created_timestamp:>'Last 7 days'" -Detailed

Retrieve detailed information about QuickScans performed within the last 7 days.
.Example
PS>Get-FalconQuickScan -Ids <id>, <id>

Retrieve detailed information about QuickScans <id> and <id>.
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
        [int] $Offset,

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
.Description
Requires 'quick-scan:read'.
.Role
quick-scan:read
.Example
PS>Get-FalconQuickScan
#>
    [CmdletBinding(DefaultParameterSetName = '/scanner/queries/scans/v1:get')]
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
.Description
Requires 'quick-scan:write'.

'Sha256' values are retrieved from files that are uploaded using 'Send-FalconSample'. Files must be uploaded
before they can be used with Falcon QuickScan.
.Parameter Ids
Sha256 hash value(s)
.Role
quick-scan:write
.Example
PS>New-FalconQuickScan -Ids <id>, <id>

Perform a Machine-Learning analysis on samples <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/scanner/entities/scans/v1:post')]
    param(
        [Parameter(ParameterSetName = '/scanner/entities/scans/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Ids = 'samples'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
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