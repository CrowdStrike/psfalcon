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
    [CmdletBinding(DefaultParameterSetName='/intel/queries/rules/v1:get')]
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
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
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
Ruleset type,used to retrieve the latest ruleset
.PARAMETER Path
Destination path
.PARAMETER Id
Ruleset identifier,used for a specific ruleset
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/entities/rules-files/v1:get')]
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
        #$PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path ''
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