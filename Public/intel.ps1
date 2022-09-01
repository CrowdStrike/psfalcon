function Get-FalconActor {
<#
.SYNOPSIS
Search for threat actors
.DESCRIPTION
Requires 'Actors (Falcon X): Read'.
.PARAMETER Id
Threat actor identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Fields
Specific fields, or a predefined collection name surrounded by two underscores [default: _basic_]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/actors/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=3)]
        [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
            'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
            'created_date|desc','last_activity_date|asc','last_activity_date|desc','last_modified_date|asc',
            'last_modified_date|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=5)]
        [string[]]$Fields,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','limit','ids','filter','offset','fields','q') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIndicator {
<#
.SYNOPSIS
Search for intelligence indicators
.DESCRIPTION
Requires 'Indicators (Falcon X): Read'.
.PARAMETER Id
Indicator identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IncludeDeleted
Include previously deleted indicators
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/indicators/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/indicators/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=3)]
        [ValidateSet('id|asc','id|desc','indicator|asc','indicator|desc','type|asc','type|desc',
            'published_date|asc','published_date|desc','last_updated|asc','last_updated|desc',
            '_marker|asc','_marker|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=5)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=5)]
        [Alias('include_deleted')]
        [boolean]$IncludeDeleted,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('sort','limit','filter','offset','include_deleted','q')
                Body = @{ root = @('ids') }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIntel {
<#
.SYNOPSIS
Search for intelligence reports
.DESCRIPTION
Requires 'Reports (Falcon X): Read'.
.PARAMETER Id
Report identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Fields
Specific fields,or a predefined collection name surrounded by two underscores [default: _basic_]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/reports/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=3)]
        [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
            'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
            'created_date|desc','last_modified_date|asc','last_modified_date|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=5)]
        [string[]]$Fields,
        [Parameter(ParameterSetName='/intel/queries/reports/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','limit','ids','filter','offset','fields','q') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconRule {
<#
.SYNOPSIS
Search for Falcon X rulesets
.DESCRIPTION
Requires 'Rules (Falcon X): Read'.
.PARAMETER Id
Ruleset identifier
.PARAMETER Type
Ruleset type
.PARAMETER Name
Ruleset name
.PARAMETER Description
Ruleset description
.PARAMETER Tag
Ruleset tag
.PARAMETER MinCreatedDate
Filter results to those created on or after a date
.PARAMETER MaxCreatedDate
Filter results to those created on or before a date
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/rules/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/rules/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\d{4,}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Mandatory,Position=1)]
        [ValidateSet('snort-suricata-master','snort-suricata-update','snort-suricata-changelog','yara-master',
            'yara-update','yara-changelog','common-event-format','netwitness',IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=2)]
        [string[]]$Name,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=3)]
        [string[]]$Description,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=4)]
        [Alias('tags')]
        [string[]]$Tag,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=5)]
        [Alias('min_created_date')]
        [int32]$MinCreatedDate,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=6)]
        [Alias('max_created_date')]
        [string]$MaxCreatedDate,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=7)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=8)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=9)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('sort','limit','max_created_date','ids','offset','min_created_date','tags',
                    'name','description','type','q')
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Receive-FalconIntel {
<#
.SYNOPSIS
Download an intelligence report
.DESCRIPTION
Requires 'Reports (Falcon X): Read'.
.PARAMETER Path
Destination path [default: <slug>.pdf]
.PARAMETER Id
Report identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/entities/report-files/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',ValueFromPipelineByPropertyName,
            Position=1)]
        [Alias('slug')]
        [string]$Path,
        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{2,}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/pdf' }
            Format = @{
                Query = @('id')
                Outfile = 'path'
            }
        }
    }
    process {
        $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'pdf'
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Receive-FalconRule {
<#
.SYNOPSIS
Download the most recent ruleset,or a specific ruleset
.DESCRIPTION
Requires 'Rules (Falcon X): Read'.
.PARAMETER Type
Ruleset type, used to retrieve the latest ruleset
.PARAMETER Path
Destination path
.PARAMETER Id
Ruleset identifier, used for a specific ruleset
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/entities/rules-files/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Mandatory,Position=1)]
        [ValidateSet('snort-suricata-master','snort-suricata-update','snort-suricata-changelog','yara-master',
            'yara-update','yara-changelog','common-event-format','netwitness',IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Mandatory,Position=2)]
        [ValidatePattern('\.(gz|gzip|zip)$')]
        [string]$Path,
        [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [int32]$Id,
        [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get')]
        [switch]$Force
    )
    begin {
        $Accept = if ($PSBoundParameters.Path -match '\.(gz|gzip)$') {
            $PSBoundParameters['format'] = 'gzip'
            'application/gzip'
        } else {
            'application/zip'
        }
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = $Accept }
            Format = @{
                Query = @('format','id','type')
                Outfile = 'path'
            }
        }
    }
    process {
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}