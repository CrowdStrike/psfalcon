function ConvertTo-FalconMlExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true, Position = 1)]
        [ValidateScript({
            if ($_.PSObject.Properties.Where({ $_.MemberType -eq 'NoteProperty' -and
            $_.Name -match '^(behaviors|device)$'})) {
                if ($_.behaviors.tactic -match '^(Machine Learning|Malware)$') {
                    $true
                } else {
                    throw "Only detections with a tactic of 'Machine Learning' or 'Malware' can be converted."
                }
            } else {
                throw 'Input object is missing required detection properties [behaviors, device].'
            }
        })]
        [object] $Detection
    )
    process {
        [PSCustomObject] @{
            value         = $_.behaviors.filepath -replace '\\Device\\HarddiskVolume\d+\\',$null
            excluded_from = @('blocking')
            groups        = if ($_.device.groups) {
                $_.device.groups
            } else {
                'all'
            }
            comment       = "Created from $($_.detection_id) by $((Show-FalconModule).UserAgent)."
        }
    }
}
function Edit-FalconMlExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ml-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 4)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            GroupIds = 'groups'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'id', 'value', 'comment')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconMlExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'value.asc', 'value.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconMlExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ml-exclusions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateSet('blocking', 'extraction')]
        [Alias('excluded_from')]
        [array] $ExcludedFrom,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [Alias('groups')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post',
            ValueFromPipelineByPropertyName = $true, Position = 4)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            ExcludedFrom = 'excluded_from'
            GroupIds     = 'groups'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'value', 'comment', 'excluded_from')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconMlExclusion {
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ml-exclusions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:delete', Position = 2)]
        [string] $Comment
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
        Invoke-Falcon @Param
    }
}