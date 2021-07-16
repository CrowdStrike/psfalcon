function Edit-FalconIoc {
<#
.Synopsis
Update custom indicators
.Parameter Id
Custom indicator identifier
.Parameter Action
Action to take when a host observes the custom indicator
.Parameter Platforms
Platform that the custom indicator applies to
.Parameter Source
The source where this custom indicator originated
.Parameter Severity
Severity level to apply to the custom indicator
.Parameter Description
Descriptive label for the custom indicator
.Parameter Filename
A common filename, or a filename in your environment (applies to hashes only)
.Parameter Tags
List of tags to apply to the custom indicator
.Parameter HostGroups
One or more Host Group identifiers to assign the custom indicator
.Parameter AppliedGlobally
Globally assign the custom indicator instead of assigning to specific Host Groups
.Parameter Expiration
The date on which the custom indicator will become inactive. When an indicator expires, its action is set
to 'no_action' but it remains in your list of custom indicators.
.Parameter Comment
Audit log comment
.Parameter RetroDetects
Generate retroactive detections for hosts that have observed the custom indicator
.Parameter IgnoreWarnings
Ignore warnings and modify all custom indicators
.Example
Edit-FalconIoc -Id <id> -Action 'prevent' -Severity 'high'
.Role
ioc:write
#>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 2)]
        [ValidateSet('no_action', 'allow', 'prevent_no_ui', 'detect', 'prevent')]
        [string] $Action,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 3)]
        [ValidateSet('linux', 'mac', 'windows')]
        [array] $Platforms,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 4)]
        [ValidateRange(1,256)]
        [string] $Source,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 5)]
        [ValidateSet('informational', 'low', 'medium', 'high', 'critical')]
        [string] $Severity,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 7)]
        [string] $Filename,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 8)]
        [array] $Tags,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 9)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostGroups,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 10)]
        [boolean] $AppliedGlobally,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 11)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}\d{2}Z)$')]
        [string] $Expiration,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 12)]
        [string] $Comment,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 13)]
        [boolean] $Retrodetects,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:patch', Position = 14)]
        [boolean] $IgnoreWarnings
    )
    begin {
        $Fields = @{
            AppliedGlobally = 'applied_globally'
            Filename        = 'metadata.filename'
            HostGroups      = 'host_groups'
            IgnoreWarnings  = 'ignore_warnings'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('retrodetects', 'ignore_warnings')
                Body  = @{
                    root       = @('comment')
                    indicators = @('id', 'tags', 'applied_globally', 'expiration', 'description',
                        'metadata.filename', 'source', 'host_groups', 'severity', 'action', 'platforms')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoc {
<#
.Synopsis
Search for custom indicators
.Parameter Ids
One or more custom indicator identifiers
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
.Example
Get-FalconIoc -Filter "type:'domain'"
.Role
ioc:read
#>
    [CmdletBinding(DefaultParameterSetName = '/iocs/queries/indicators/v1:get')]
    param(
        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get', Position = 2)]
        [ValidateSet('action', 'applied_globally', 'metadata.av_hits', 'metadata.company_name.raw', 'created_by',
            'created_on', 'expiration', 'expired', 'metadata.filename.raw', 'modified_by', 'modified_on',
            'metadata.original_filename.raw', 'metadata.product_name.raw', 'metadata.product_version',
            'severity_number', 'source', 'type', 'value')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get', Position = 3)]
        [ValidateRange(1,2000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get')]
        [Parameter(ParameterSetName = '/iocs/combined/indicator/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/iocs/queries/indicators/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'filter', 'offset', 'limit', 'sort')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoc {
<#
.Synopsis
Create custom indicators
.Parameter Array
An array of custom indicators to create in a single request
.Parameter Type
Custom indicator type
.Parameter Value
String representation of the custom indicator
.Parameter Action
Action to take when a host observes the custom indicator
.Parameter Platforms
Platform that the custom indicator applies to
.Parameter Source
The source where this custom indicator originated
.Parameter Severity
Severity level to apply to the custom indicator
.Parameter Description
Descriptive label for the custom indicator
.Parameter Filename
A common filename, or a filename in your environment (applies to hashes only)
.Parameter Tags
List of tags to apply to the custom indicator
.Parameter HostGroups
One or more Host Group identifiers to assign the custom indicator
.Parameter AppliedGlobally
Globally assign the custom indicator instead of assigning to specific Host Groups
.Parameter Expiration
The date on which the custom indicator will become inactive. When an indicator expires, its action is set
to 'no_action' but it remains in your list of custom indicators.
.Parameter Comment
Audit log comment
.Parameter RetroDetects
Generate retroactive detections for hosts that have observed the custom indicator
.Parameter IgnoreWarnings
Ignore warnings and create all custom indicators
.Example
New-FalconIoc -Array @(@{ type = 'domain'; value = 'example.com'; platforms = @('windows'); action = 'detect';
severity = 'low'; applied_globally = $true}, @{ type = 'ipv4'; value = '93.184.216.34'; platforms = @('windows',
'mac','linux'); action = 'detect'; severity = 'low'; host_groups = @('<id>', '<id>')})
.Example
New-FalconIoc -Type domain -Value example.com -Platforms windows -Action detect -Severity low -AppliedGlobally
$true
.Role
ioc:write
#>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Mandatory = $true, Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Mandatory = $true, Position = 3)]
        [ValidateSet('no_action', 'allow', 'prevent_no_ui', 'detect', 'prevent')]
        [string] $Action,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Mandatory = $true, Position = 4)]
        [ValidateSet('linux', 'mac', 'windows')]
        [array] $Platforms,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 5)]
        [ValidateRange(1,256)]
        [string] $Source,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 6)]
        [ValidateSet('informational', 'low', 'medium', 'high', 'critical')]
        [string] $Severity,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 7)]
        [string] $Description,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 8)]
        [string] $Filename,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 9)]
        [array] $Tags,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 10)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostGroups,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 11)]
        [boolean] $AppliedGlobally,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 12)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}\d{2}Z)$')]
        [string] $Expiration,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 13)]
        [Parameter(ParameterSetName = 'array', Position = 2)]
        [string] $Comment,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 14)]
        [Parameter(ParameterSetName = 'array', Position = 3)]
        [boolean] $Retrodetects,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:post', Position = 15)]
        [Parameter(ParameterSetName = 'array', Position = 4)]
        [boolean] $IgnoreWarnings
    )
    begin {
        $Fields = @{
            AppliedGlobally = 'applied_globally'
            Array           = 'indicators'
            Filename        = 'metadata.filename'
            HostGroups      = 'host_groups'
            IgnoreWarnings  = 'ignore_warnings'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/iocs/entities/indicators/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('retrodetects', 'ignore_warnings')
                Body  = @{
                    root       = @('comment', 'indicators')
                    indicators = @('tags', 'applied_globally', 'expiration', 'description', 'value',
                        'metadata.filename', 'type', 'source', 'host_groups', 'severity', 'action', 'platforms')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoc {
<#
.Synopsis
Remove custom indicators
.Parameter Ids
One or more custom indicator identifiers
.Parameter Filter
Falcon Query Language expression to find custom indicators for removal (takes precedence over 'Ids')
.Parameter Comment
Audit log comment
.Role
ioc:write
#>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:delete', Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:delete', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/iocs/entities/indicators/v1:delete', Position = 3)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format    = @{
                Query = @('ids', 'filter', 'comment')
            }
        }
    }
    process {
        if (!$PSBoundParameters.Filter -and !$PSBoundParameters.Ids) {
            throw "'Filter' or 'Ids' must be provided."
        } else {
            Invoke-Falcon @Param
        }
    }
}