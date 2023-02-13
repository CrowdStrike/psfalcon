function ConvertTo-FalconIoaExclusion {
<#
.SYNOPSIS
Output required fields to create an Indicator of Attack exclusion from a Falcon detection
.DESCRIPTION
Uses the 'behaviors' and 'device' properties of a detection to generate the necessary fields to create a new
Indicator of Attack exclusion. Specfically, it maps the following properties these fields:

behaviors.behavior_id  > pattern_id
behaviors.display_name > pattern_name
behaviors.cmdline      > cl_regex
behaviors.filepath     > ifn_regex
device.groups          > groups

The 'cl_regex' and 'ifn_regex' fields are escaped using the [regex]::Escape() PowerShell accelerator. The
'ifn_regex' output also replaces the NT device path ('Device/HarddiskVolume') with a wildcard.

If the detection involves a device that is not in any groups, it uses 'all' to target all host groups.

The resulting output can be passed to 'New-FalconIoaExclusion' to create an exclusion.
.PARAMETER Detection
Falcon detection content, including 'behaviors' and 'device'
.LINK
https://github.com/crowdstrike/psfalcon/wiki/ConvertTo-FalconIoaExclusion
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=1)]
        [object]$Detection
    )
    begin { [System.Collections.Generic.List[PSCustomObject]]$Output = @() }
    process {
        if ($Detection.behaviors -and $Detection.device) {
            @($Detection.behaviors).Where({ $_.tactic -notmatch '^(Machine Learning|Malware)$' }).foreach{
                $Output.Add(([PSCustomObject]@{
                    pattern_id = $_.behavior_id
                    pattern_name = $_.display_name
                    cl_regex = [regex]::Escape($_.cmdline) -replace '(\\ {1,})+','\s+'
                    ifn_regex = [regex]::Escape($_.filepath) -replace '\\\\Device\\\\HarddiskVolume\d+','.*'
                    groups = if ($Detection.device.groups) { $Detection.device.groups } else { 'all' }
                    comment = "Created from $($Detection.detection_id) by $((Show-FalconModule).UserAgent)."
                }))
            }
        } else {
            foreach ($Property in @('behaviors','device')) {
                if (!$Detection.$Property) {
                    throw "[ConvertTo-FalconMlExclusion] Missing required '$Property' property."
                }
            }
        }
    }
    end { if ($Output) { @($Output | Group-Object pattern_id).foreach{ $_.Group | Select-Object -First 1 }}}
}
function Edit-FalconIoaExclusion {
<#
.SYNOPSIS
Modify an Indicator of Attack exclusion
.DESCRIPTION
Requires 'IOA Exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER ClRegex
Command line RegEx
.PARAMETER IfnRegex
Image Filename RegEx
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER Description
Exclusion description
.PARAMETER Comment
Audit log comment
.PARAMETER PatternId
Indicator of Attack pattern identifier
.PARAMETER PatternName
Indicator of Attack pattern name
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconIoaExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:patch',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.responses.IoaExclusionV1',ParameterSetName='/policy/entities/ioa-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [Alias('cl_regex')]
        [string]$ClRegex,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [Alias('ifn_regex')]
        [string]$IfnRegex,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=4)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=5)]
        [string]$Description,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=6)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=7)]
        [Alias('pattern_id')]
        [string]$PatternId,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
            Position=8)]
        [Alias('pattern_name')]
        [string]$PatternName,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^([a-fA-F0-9]{32}|all)$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('cl_regex','ifn_regex','groups','name','id','description','comment','pattern_id',
                        'pattern_name')
                }
            }
            Schema = 'responses.IoaExclusionV1'
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess('Edit-FalconIoaExclusion','Test-GroupId')) {
            if ($PSBoundParameters.GroupId) {
                if ($PSBoundParameters.GroupId.id) {
                    # Filter to 'id' if supplied with 'detailed' objects
                    [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id
                }
                @($PSBoundParameters.GroupId).foreach{
                    if ($_ -notmatch '^([a-fA-F0-9]{32}|all)$') {
                        throw "'$_' is not a valid Host Group identifier."
                    }
                }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconIoaExclusion {
<#
.SYNOPSIS
Search for Indicator of Attack exclusions
.DESCRIPTION
Requires 'IOA Exclusions: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/ioa-exclusions/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.responses.IoaExclusionV1',ParameterSetName='/policy/entities/ioa-exclusions/v1:get')]
    [OutputType([string],ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=2)]
        [ValidateSet('applied_globally.asc','applied_globally.desc','created_by.asc','created_by.desc',
            'created_on.asc','created_on.desc','last_modified.asc','last_modified.desc','modified_by.asc',
            'modified_by.desc','name.asc','name.desc','pattern_id.asc','pattern_id.desc','pattern_name.asc',
            'pattern_name.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/policy/entities/ioa-exclusions/v1:get' { 'responses.IoaExclusionV1' }
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
function New-FalconIoaExclusion {
<#
.SYNOPSIS
Create an Indicator of Attack exclusion
.DESCRIPTION
'ConvertTo-FalconIoaExclusion' can be used to generate the required Indicator of Attack exclusion properties
using an existing detection.

Requires 'IOA Exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER PatternId
Indicator of Attack pattern identifier
.PARAMETER PatternName
Indicator of Attack pattern name
.PARAMETER ClRegex
Command line RegEx
.PARAMETER IfnRegex
Image Filename RegEx
.PARAMETER GroupId
Host group identifier, or leave undefined to apply to all hosts
.PARAMETER Description
Exclusion description
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconIoaExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.responses.IoaExclusionV1',ParameterSetName='/policy/entities/ioa-exclusions/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d+$')]
        [Alias('pattern_id')]
        [string]$PatternId,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('pattern_name')]
        [string]$PatternName,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [Alias('cl_regex')]
        [string]$ClRegex,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=5)]
        [Alias('ifn_regex')]
        [string]$IfnRegex,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
            Position=7)]
        [Alias('groups','GroupIds')]
        [object[]]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
            Position=8)]
        [string]$Description,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
            Position=9)]
        [string]$Comment
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('cl_regex','ifn_regex','groups','name','pattern_id','pattern_name',
                        'description','comment')
                }
            }
            Schema = 'responses.IoaExclusionV1'
        }
    }
    process {
        if ($PSBoundParameters.GroupId.id) {
            # Filter to 'id' if supplied with 'detailed' objects
            [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id
        }
        if ($PSBoundParameters.GroupId -eq 'all') {
            # Remove 'all' from 'GroupId', and remove 'GroupId' if 'all' was the only value
            $PSBoundParameters.GroupId = @($PSBoundParameters.GroupId).Where({ $_ -ne 'all' })
            if ([string]::IsNullOrEmpty($PSBoundParameters.GroupId)) { [void]$PSBoundParameters.Remove('GroupId') }
        }
        if ($PSBoundParameters.GroupId) {
            @($PSBoundParameters.GroupId).foreach{
                if ($_ -notmatch '^[a-fA-F0-9]{32}$') { throw "'$_' is not a valid Host Group identifier." }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Remove-FalconIoaExclusion {
<#
.SYNOPSIS
Remove Indicator of Attack exclusions
.DESCRIPTION
Requires 'IOA Exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconIoaExclusion
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:delete',Mandatory,
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