function Edit-FalconDetection {
<#
.Synopsis
Modify the state, assignee, and visibility of detections
.Parameter Ids
Detection identifier(s)
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
        $Fields = @{
            AssignedToUuid = 'assigned_to_uuid'
            ShowInUi       = 'show_in_ui'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
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
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers  = @{
                ContentType = 'application/json'
            }
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
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