function Get-FalconRule {
<#
.Synopsis
Search for intelligence rulesets
.Parameter Ids
One or more ruleset identifiers
.Parameter Type
Ruleset type
.Parameter Name
Ruleset name
.Parameter Description
Ruleset description
.Parameter Tags
One or more ruleset tags
.Parameter MinCreatedDate
Filter results to those created on or after a date
.Parameter MaxCreatedDate
Filter results to those created on or before a date
.Parameter Query
Perform a generic substring search across available fields
.Parameter Offset
Position to begin retrieving results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconx-rules:read
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/rules/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{4,}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('snort-suricata-master', 'snort-suricata-update', 'snort-suricata-changelog', 'yara-master',
            'yara-update', 'yara-changelog', 'common-event-format', 'netwitness')]
        [string] $Type,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 2)]
        [array] $Name,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 3)]
        [array] $Description,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 4)]
        [array] $Tags,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 5)]
        [int] $MinCreatedDate,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 6)]
        [string] $MaxCreatedDate,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 7)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 8)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 9)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get', Position = 10)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/intel/queries/rules/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            MaxCreatedDate = 'max_created_date'
            MinCreatedDate = 'min_created_date'
            Query          = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'limit', 'max_created_date', 'ids', 'offset', 'min_created_date', 'tags',
                    'name', 'description', 'type', 'q')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconRule {
<#
.Synopsis
Download the most recent ruleset, or a specific ruleset
.Parameter Id
Ruleset identifier, used for a specific ruleset
.Parameter Type
Ruleset type, used to retrieve the latest ruleset
.Parameter Path
Destination path
.Role
falconx-rules:read
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/entities/rules-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/rules-files/v1:get', Mandatory = $true, Position = 1)]
        [int] $Id,

        [Parameter(ParameterSetName = '/intel/entities/rules-latest-files/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidateSet('snort-suricata-master', 'snort-suricata-update', 'snort-suricata-changelog', 'yara-master',
            'yara-update', 'yara-changelog', 'common-event-format', 'netwitness')]
        [string] $Type,

        [Parameter(ParameterSetName = '/intel/entities/rules-files/v1:get', Mandatory = $true, Position = 2)]
        [Parameter(ParameterSetName = '/intel/entities/rules-latest-files/v1:get', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('\.(gzip|zip)$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        if ($PSBoundParameters.Path -match '\.gzip$') {
            $PSBoundParameters.Add('format', 'gzip')
            $Accept = 'application/gzip'
        } else {
            $Accept = 'application/zip'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = $Accept
            }
            Format   = @{
                Query   = @('format', 'id', 'type')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}