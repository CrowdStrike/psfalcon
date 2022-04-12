function Get-FalconRemediation {
<#
.SYNOPSIS
Retrieve detail about remediations specified in a Falcon Spotlight vulnerability
.DESCRIPTION
Requires 'Spotlight Vulnerabilities: Read'.
.PARAMETER Id
Remediation identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Spotlight
#>
    [CmdletBinding(DefaultParameterSetName='/spotlight/entities/remediations/v2:get')]
    param(
        [Parameter(ParameterSetName='/spotlight/entities/remediations/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Alias('ids')]
        [object[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{
                if ($_.apps.remediation.ids) {
                    # Use 'apps.remediation.ids' when supplied with a detailed vulnerability object
                    @($_.apps.remediation.ids).foreach{ [void]$IdArray.Add($_) }
                } elseif ($_ -is [string]) {
                    if ($_ -notmatch '^\w{32}$') {
                        throw "'$_' is not a valid remediation identifier."
                    } else {
                        [void]$IdArray.Add($_)
                    }
                }
            }
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconVulnerability {
<#
.SYNOPSIS
Search for Falcon Spotlight vulnerabilities
.DESCRIPTION
Requires 'Spotlight Vulnerabilities: Read'.
.PARAMETER Id
Vulnerability identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Facet
Include additional properties
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Sort
Property and direction to sort results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Spotlight
#>
    [CmdletBinding(DefaultParameterSetName='/spotlight/queries/vulnerabilities/v1:get')]
    param(
        [Parameter(ParameterSetName='/spotlight/entities/vulnerabilities/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Mandatory,Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Position=2)]
        [ValidateSet('cve','evaluation_logic','host_info','remediation',IgnoreCase=$false)]
        [string[]]$Facet,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get',Position=3)]
        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Position=3)]
        [ValidateSet('created_timestamp.asc','created_timestamp.desc','closed_timestamp.asc',
            'closed_timestamp.desc','updated_timestamp.asc','updated_timestamp.desc',IgnoreCase=$false)]
        [string]$Sort,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get',Position=4)]
        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Position=4)]
        [ValidateRange(1,400)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get',Position=5)]
        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Position=5)]
        [string]$After,

        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get',Mandatory)]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get')]
        [Parameter(ParameterSetName='/spotlight/combined/vulnerabilities/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/spotlight/queries/vulnerabilities/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('after','sort','ids','filter','limit','facet') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconVulnerabilityLogic {
<#
.SYNOPSIS
Search for Falcon Spotlight vulnerability evaluation logic
.DESCRIPTION
Requires 'Spotlight Vulnerabilities: Read'.
.PARAMETER Id
Vulnerability logic identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Spotlight
#>
    [CmdletBinding(DefaultParameterSetName='/spotlight/queries/evaluation-logic/v1:get')]
    param(
        [Parameter(ParameterSetName='/spotlight/entities/evaluation-logic/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('ids','apps')]
        [object[]]$Id,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get',Mandatory,Position=1)]
        [string]$Filter,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get',Position=2)]
        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get',Position=2)]
        [string]$Sort,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get',Position=3)]
        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get',Position=3)]
        [int]$Limit,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get',Position=4)]
        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get',Position=4)]
        [string]$After,

        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get',Mandatory)]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get')]
        [Parameter(ParameterSetName='/spotlight/combined/evaluation-logic/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/spotlight/queries/evaluation-logic/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('after','sort','ids','filter','limit') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{
                if ($_.apps.evaluation_logic.id) {
                    # Use 'apps.evaluation_logic.id' when supplied with a detailed vulnerability object
                    [void]$IdArray.Add($_.apps.evaluation_logic.id)
                } elseif ($_ -is [string]) {
                    if ($_ -notmatch '^\w{32}$') {
                        throw "'$_' is not a valid vulnerability evaluation logic identifier."
                    } else {
                        [void]$IdArray.Add($_)
                    }
                }
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}