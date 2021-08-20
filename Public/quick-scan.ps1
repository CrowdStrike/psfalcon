function Get-FalconQuickScan {
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