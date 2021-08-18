function Edit-FalconIoaExclusion {
<#
.Synopsis
Modify Indicator of Attack exclusions
.Description
Requires 'self-service-ioa-exclusions:write'.
.Parameter Id
Indicator of Attack exclusion identifier
.Parameter Name
Indicator of Attack exclusion name
.Parameter ClRegex
Command line RegEx
.Parameter IfnRegex
Image Filename RegEx
.Parameter GroupIds
Host Group identifier(s) or 'all'
.Parameter Description
Indicator of Attack exclusion description
.Parameter Comment
Audit log comment
.Role
self-service-ioa-exclusions:write
.Example
PS>Edit-FalconIoaExclusion -Id <id> -IfnRegex '.*\\Windows\\System32\\choice1\.exe'

Modify the existing Indicator of Attack exclusion <id> to set 'ifn_regex' to '.*\\Windows\\System32\\choice1\.exe'.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 3)]
        [string] $ClRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 4)]
        [string] $IfnRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 5)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 7)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            ClRegex  = 'cl_regex'
            GroupIds = 'groups'
            IfnRegex = 'ifn_regex'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('cl_regex', 'ifn_regex', 'groups', 'name', 'id', 'description', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaExclusion {
<#
.Synopsis
Search for Indicator of Attack exclusions
.Description
Requires 'self-service-ioa-exclusions:read'.
.Parameter Ids
Indicator of Attack exclusion identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
self-service-ioa-exclusions:read
.Example
PS>Get-FalconIoaExclusion -Detailed

Return the first set of detailed results about Indicator of Attack exclusions.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'name.asc', 'name.desc', 'pattern_id.asc', 'pattern_id.desc', 'pattern_name.asc',
            'pattern_name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
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
function Remove-FalconIoaExclusion {
<#
.Synopsis
Delete Indicator of Attack exclusions
.Description
Requires 'self-service-ioa-exclusions:write'.
.Parameter Ids
Indicator of Attack exclusion identifier(s)
.Parameter Comment
Audit log comment
.Role
self-service-ioa-exclusions:write
.Example
PS>Remove-FalconIoaExclusion -Ids <id>, <id>

Delete Indicator of Attack exclusions <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete', Position = 2)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}