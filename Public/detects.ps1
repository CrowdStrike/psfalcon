function Edit-FalconDetection {
<#
.Synopsis
Modify the state, assignee, and visibility of detections
.Parameter Ids
One or more detection identifiers
.Parameter Status
Detection status
.Parameter ShowInUi
Visible within the Falcon UI [default: $true]
.Parameter AssignedToUuid
User identifier for assignment
.Parameter Comment
Detection comment
.Role
detects:write
#>
    [CmdletBinding(DefaultParameterSetName =  '/detects/entities/detects/v2:patch')]
    param(
        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 2)]
        [ValidateSet('new', 'in_progress', 'true_positive', 'false_positive', 'ignored', 'closed', 'reopened')]
        [string] $Status,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $AssignedToUuid,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 4)]
        [string] $Comment,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 5)]
        [boolean] $ShowInUi
    )
    begin {
        @('AssignedToUuid', 'ShowInUi').foreach{
            if ($PSBoundParameters.$_) {
                # Rename parameter for API submission
                $Field = switch ($_) {
                    'AssignedToUuid' { 'assigned_to_uuid' }
                    'ShowInUi'       { 'show_in_ui' }
                }
                $PSBoundParameters.Add($Field, $PSBoundParameters.$_)
                [void] $PSBoundParameters.Remove($_)
            }
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    root = @('show_in_ui', 'comment', 'assigned_to_uuid', 'status', 'ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDetection {
<#
.Synopsis
Search for detections
.Parameter Ids
Retrieve information for specific detection identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
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
detects:read
#>
    [CmdletBinding(DefaultParameterSetName = '/detects/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName = '/detects/entities/summaries/GET/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $Total
    )
    begin {
        if ($PSBoundParameters.Query) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('q', $PSBoundParameters.Query)
            [void] $PSBoundParameters.Remove('Query')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers  = @{
                ContentType = 'application/json'
            }
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter', 'q', 'sort', 'limit', 'offset')
                Body  = @{
                    root = @('ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDetectionAggregate {
<#
.Synopsis
Get detect aggregates as specified via json in request body.
.Role
detects:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [int64] $MinDocCount,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Q,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Interval,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Field,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Missing,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [int32] $Size,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Type,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $To,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $From,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $TimeZone,

        [Parameter(ParameterSetName = '/detects/aggregates/detects/GET/v1:post', Mandatory = $true)]
        [string] $Name
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    root = @('min_doc_count', 'q', 'interval', 'sort', 'field', 'missing', 'size', 'type',
                        'filter', 'time_zone', 'name')
                    date_ranges = @('to', 'from')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}