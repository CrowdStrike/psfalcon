function Get-FalconQuickScan {
    [CmdletBinding(DefaultParameterSetName = '/scanner/queries/scans/v1:get')]
    param(
        [Parameter(ParameterSetName = '/scanner/entities/scans/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/scanner/queries/scans/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
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
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Query = @('sort', 'ids', 'offset', 'filter', 'limit') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconQuickScanQuota {
    [CmdletBinding(DefaultParameterSetName = '/scanner/queries/scans/v1:get')]
    param()
    process {
        $Request = Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName -RawOutput
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
        $Fields = @{ Ids = 'samples' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ root = @('samples') }}
        }
        Invoke-Falcon @Param
    }
}