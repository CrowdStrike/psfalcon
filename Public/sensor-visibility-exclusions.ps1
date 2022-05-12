function Edit-FalconSvExclusion {
<#
.SYNOPSIS
Modify a Sensor Visibility exclusion
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Id
Exclusion identifier
.PARAMETER Value
RegEx pattern value
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=1)]
        [string]$Value,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('groups','id','value','comment') }}
        }
    }
    process {
        if ($PSBoundParameters.GroupId.id) {
            # Filter to 'id' if supplied with 'detailed' objects
            [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id
        }
        if ($PSBoundParameters.GroupId) {
            @($PSBoundParameters.GroupId).foreach{
                if ($_ -notmatch '^([a-fA-F0-9]{32}|all)$') { throw "'$_' is not a valid Host Group identifier." }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconSvExclusion {
<#
.SYNOPSIS
Search for Sensor Visibility exclusions
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Read'.
.PARAMETER Id
Exclusion identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/sv-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=2)]
        [ValidateSet('applied_globally.asc','applied_globally.desc','created_by.asc','created_by.desc',
            'created_on.asc','created_on.desc','last_modified.asc','last_modified.desc','modified_by.asc',
            'modified_by.desc','value.asc','value.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
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
function New-FalconSvExclusion {
<#
.SYNOPSIS
Create a Sensor Visibility exclusion
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER Comment
Audit log comment
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Value,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Comment
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('groups','value','comment') }}
        }
    }
    process {
        if ($PSBoundParameters.GroupId.id) {
            # Filter to 'id' if supplied with 'detailed' objects
            [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id
        }
        if ($PSBoundParameters.GroupId) {
            @($PSBoundParameters.GroupId).foreach{
                if ($_ -notmatch '^([a-fA-F0-9]{32}|all)$') { throw "'$_' is not a valid Host Group identifier." }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Remove-FalconSvExclusion {
<#
.SYNOPSIS
Remove Sensor Visibility exclusions
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','comment') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ if ($PSCmdlet.ShouldProcess($_)) { $List.Add($_) }}}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}