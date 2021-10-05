function ConvertTo-FalconIoaExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true, Position = 1)]
        [ValidateScript({
            if ($_.PSObject.Properties.Where({ $_.MemberType -eq 'NoteProperty' -and
            $_.Name -match '^(behaviors|device)$'})) {
                if ($_.behaviors.tactic -match '^(Machine Learning|Malware)$') {
                    throw "Tactics 'Machine Learning' and 'Malware' are used with Machine Learning exclusions."
                } else {
                    $true
                }
            } else {
                throw 'Input object is missing required detection properties [behaviors, device].'
            }
        })]
        [object] $Detection
    )
    process {
        [PSCustomObject] @{
            pattern_id   = $_.behaviors.behavior_id
            pattern_name = $_.behaviors.display_name
            cl_regex     = [regex]::Escape($_.behaviors.cmdline) -replace '(\\ {1,})+','\s+'
            ifn_regex    = [regex]::Escape($_.behaviors.filepath) -replace '\\\\Device\\\\HarddiskVolume\d+','.*'
            groups       = if ($_.device.groups) {
                $_.device.groups
            } else {
                'all'
            }
            comment     = "Created from $($_.detection_id) by $((Show-FalconModule).UserAgent)."
        }
    }
}
function Edit-FalconIoaExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 3)]
        [string] $ClRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 4)]
        [string] $IfnRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 5)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 7)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            ClRegex  = 'cl_regex'
            GroupIds = 'groups'
            IfnRegex = 'ifn_regex'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('cl_regex', 'ifn_regex', 'groups', 'name', 'id', 'description', 'comment')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'name.asc', 'name.desc', 'pattern_id.asc', 'pattern_id.desc', 'pattern_name.asc',
            'pattern_name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoaExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidatePattern('^\d+$')]
        [Alias('pattern_id')]
        [string] $PatternId,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 3)]
        [Alias('pattern_name')]
        [string] $PatternName,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 4)]
        [Alias('cl_regex')]
        [string] $ClRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 5)]
        [Alias('ifn_regex')]
        [string] $IfnRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post',
            ValueFromPipelineByPropertyName = $true, Position = 7)]
        [ValidatePattern('^(\w{32}|all)$')]
        [Alias('groups')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Position = 8)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:post', Position = 9)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            ClRegex       = 'cl_regex'
            GroupIds      = 'groups'
            IfnRegex      = 'ifn_regex'
            PatternId     = 'pattern_id'
            PatternName   = 'pattern_name'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('cl_regex', 'ifn_regex', 'groups', 'name', 'pattern_id', 'pattern_name',
                        'description', 'comment')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoaExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete', Position = 2)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}