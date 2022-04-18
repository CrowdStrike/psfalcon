function Edit-FalconDetection {
<#
.SYNOPSIS
Modify detections
.DESCRIPTION
Requires 'Detections: Write'.
.PARAMETER Status
Detection status
.PARAMETER Comment
Detection comment
.PARAMETER ShowInUi
Visible within the Falcon UI [default: $true]
.PARAMETER AssignedToUuid
User identifier for assignment
.PARAMETER Id
Detection identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/detects/v2:patch')]
    param(
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Position=1)]
        [ValidateSet('new','in_progress','true_positive','false_positive','ignored','closed','reopened',
            IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Position=2)]
        [ValidateScript({
            if ($PSBoundParameters.Status) { $true } else { throw "A valid 'status' value must also be supplied." }
        })]
        [string]$Comment,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Position=3)]
        [Alias('show_in_ui')]
        [boolean]$ShowInUi,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',ValueFromPipelineByPropertyName,
           Position=4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('assigned_to_uuid','uuid')]
        [string]$AssignedToUuid,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [Alias('Ids','detection_id','detection_ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('show_in_ui','comment','assigned_to_uuid','status','ids') }}
            Max = 1000
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconDetection {
<#
.SYNOPSIS
Search for detections
.DESCRIPTION
Requires 'Detections: Read'.
.PARAMETER Id
Detection identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/detects/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/summaries/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [Alias('Ids','detection_id','detection_ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=5)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('filter','q','sort','limit','offset')
            }
            Max = 1000
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