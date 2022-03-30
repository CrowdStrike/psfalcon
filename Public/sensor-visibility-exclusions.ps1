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
.PARAMETER GroupIds
Host group identifier or 'all'
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Position=2)]
        [string]$Value,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Position=3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [Alias('groups','GroupIds')]
        [string[]]$GroupId,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Position=4)]
        [string]$Comment,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('groups','id','value','comment') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
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
        [ValidatePattern('^\w{32}$')]
        [Alias('ids')]
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

        [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=4)]
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
function New-FalconSvExclusion {
<#
.SYNOPSIS
Create a Sensor Visibility exclusion
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER GroupIds
Host group identifier or 'all'
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,Position=1)]
        [string]$Value,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Position=2)]
        [string]$Comment,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,Position=3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [Alias('groups','id','group_ids','GroupIds')]
        [string[]]$GroupId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('groups','value','comment') }}
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($GroupId) { @($GroupId).foreach{ [void]$IdArray.Add($_) }}
    }
    end {
        if ($IdArray) { $PSBoundParameters['GroupId'] = @($IdArray | Select-Object -Unique) }
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
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:delete')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Position=1)]
        [string]$Comment,

        [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','comment') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}
    }
    end {
        if ($IdArray) { $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}