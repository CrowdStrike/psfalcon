function Get-FalconScheduledReport {
    [CmdletBinding(DefaultParameterSetName = '/reports/queries/scheduled-reports/v1:get')]
    param(
        [Parameter(ParameterSetName = '/reports/entities/scheduled-reports/v1:get', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/reports/entities/report-executions/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('created_on','description','expiration_on','last_execution.last_updated_on',
            'last_execution.status','last_updated_on','name','next_execution_on','shared_with','start_on',
            'status','stop_on','type','user_id','result_metadata','scheduled_report_id')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Position = 3)]
        [ValidateSet('created_on.asc','created_on.desc','last_updated_on.asc','last_updated_on.desc',
            'last_execution_on.asc','last_execution_on.desc','next_execution_on.asc','next_execution_on.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get', Mandatory = $true)]
        [Parameter(ParameterSetName = '/reports/entities/report-executions/v1:get', Mandatory = $true)]
        [switch] $Execution,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get')]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get')]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/reports/queries/scheduled-reports/v1:get')]
        [Parameter(ParameterSetName = '/reports/queries/report-executions/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'limit', 'ids', 'filter', 'offset', 'q')
            }
        }
        if ($Param.Inputs.Execution -and $Param.Inputs.Detailed) {
            $Param.Inputs.Remove('Detailed')
            $Request = Invoke-Falcon @Param
            if ($Request) {
                & $MyInvocation.MyCommand.Name -Execution -Ids $Request
            }
        } else {
            Invoke-Falcon @Param
        }
        
    }
}
function Invoke-FalconScheduledReport {
    [CmdletBinding(DefaultParameterSetName = '/reports/entities/scheduled-reports/execution/v1:post')]
    param(
        [Parameter(ParameterSetName = '/reports/entities/scheduled-reports/execution/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id
    )
    begin {
        if (!$Script:Falcon) {
            Request-FalconToken
        }
    }
    process {
        $Param = @{
            Path    = @($Script:Falcon.Hostname, ($PSCmdlet.ParameterSetName).Split(':')[0]) -join $null
            Method  = ($PSCmdlet.ParameterSetName).Split(':')[-1]
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body = '[{ "id": "' + $PSBoundParameters.Id + '" }]'
        }
        Write-Result ($Script:Falcon.Api.Invoke($Param))
    }
}
function Receive-FalconScheduledReport {
    [CmdletBinding(DefaultParameterSetName = '/reports/entities/report-executions-download/v1:get')]
    param(
        [Parameter(ParameterSetName = '/reports/entities/report-executions-download/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/reports/entities/report-executions-download/v1:get', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('\.gzip$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    process {
        $PSBoundParameters['ids'] = @( $PSBoundParameters.Id )
        [void] $PSBoundParameters.Remove('id')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Query   = @('ids')
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
function Redo-FalconScheduledReport {
    [CmdletBinding(DefaultParameterSetName = '/reports/entities/report-executions-retry/v1:post')]
    param(
        [Parameter(ParameterSetName = '/reports/entities/report-executions-retry/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id
    )
    begin {
        if (!$Script:Falcon) {
            Request-FalconToken
        }
    }
    process {
        $Param = @{
            Path    = @($Script:Falcon.Hostname, ($PSCmdlet.ParameterSetName).Split(':')[0]) -join $null
            Method  = ($PSCmdlet.ParameterSetName).Split(':')[-1]
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body = '[{ "id": "' + $PSBoundParameters.Id + '" }]'
        }
        Write-Result ($Script:Falcon.Api.Invoke($Param))
    }
}