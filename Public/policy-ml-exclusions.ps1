function ConvertTo-FalconMlExclusion {
<#
.SYNOPSIS
Output required fields to create a Machine Learning exclusion from a Falcon detection
.DESCRIPTION
Uses the 'behaviors' and 'device' properties of a detection to generate the necessary fields to create a new
Machine Learning exclusion. Specfically, it maps the following properties these fields:

behaviors.filepath > value
device.groups      > groups

The 'value' field is stripped of any leading NT file path ('Device/HarddiskVolume').

If the detection involves a device that is not in any groups,it uses 'all' to target all host groups.

The resulting output can be passed to 'New-FalconMlExclusion' to create an exclusion.
.PARAMETER Detection
Falcon detection content, including 'behaviors' and 'device'
.LINK
https://github.com/crowdstrike/psfalcon/wiki/ConvertTo-FalconMlExclusion
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=1)]
        [System.Object]$Detection
    )
    begin { [System.Collections.Generic.List[object]]$Output = @() }
    process {
        if ($_.behaviors -and $_.device) {
            @($_.behaviors).Where({ $_.tactic -match '^(Machine Learning|Malware)$' }).foreach{
                $Output.Add(([PSCustomObject]@{
                    value = $_.filepath -replace '\\Device\\HarddiskVolume\d+\\',$null
                    excluded_from = @('blocking')
                    groups = if ($Detection.device.groups) { $Detection.device.groups } else { 'all' }
                    comment = "Created from $($Detection.detection_id) by $((Show-FalconModule).UserAgent)."
                }))
            }
        } else {
            foreach ($Property in @('behaviors','device')) {
                if (!$_.$Property) {
                    throw "[ConvertTo-FalconMlExclusion] Missing required '$Property' property."
                }
            }
        }
    }
    end { if ($Output) { @($Output | Group-Object value).foreach{ $_.Group | Select-Object -First 1 }}}
}
function Edit-FalconMlExclusion {
<#
.SYNOPSIS
Modify a Machine Learning exclusion
.DESCRIPTION
Requires 'Machine Learning Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconMlExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ml-exclusions/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=1)]
        [string]$Value,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:patch',Mandatory,
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
function Get-FalconMlExclusion {
<#
.SYNOPSIS
Search for Machine Learning exclusions
.DESCRIPTION
Requires 'Machine Learning Exclusions: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMlExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/ml-exclusions/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:get',ValueFromPipelineByPropertyName,
            ValueFromPipeline,Mandatory)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get',Position=2)]
        [ValidateSet('applied_globally.asc','applied_globally.desc','created_by.asc','created_by.desc',
            'created_on.asc','created_on.desc','last_modified.asc','last_modified.desc','modified_by.asc',
            'modified_by.desc','value.asc','value.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/queries/ml-exclusions/v1:get')]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function New-FalconMlExclusion {
<#
.SYNOPSIS
Create a Machine Learning exclusion
.DESCRIPTION
'ConvertTo-FalconMlExclusion' can be used to generate the required Machine Learning exclusion properties using
an existing detection.

Requires 'Machine Learning Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER ExcludedFrom
Actions to exclude
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconMlExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ml-exclusions/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Value,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('blocking','extraction',IgnoreCase=$false)]
        [Alias('excluded_from')]
        [string[]]$ExcludedFrom,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [string]$Comment
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('groups','value','comment','excluded_from') }}
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
function Remove-FalconMlExclusion {
<#
.SYNOPSIS
Remove Machine Learning exclusions
.DESCRIPTION
Requires 'Machine Learning Exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconMlExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ml-exclusions/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/ml-exclusions/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}