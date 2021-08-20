function Get-FalconReport {
    [CmdletBinding(DefaultParameterSetName = '/falconx/queries/reports/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falconx/entities/reports/v1:get', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/falconx/entities/report-summaries/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falconx/entities/report-summaries/v1:get', Mandatory = $true)]
        [switch] $Summary,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falconx/queries/reports/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter', 'offset', 'sort', 'ids', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconSubmission {
    [CmdletBinding(DefaultParameterSetName = '/falconx/queries/submissions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falconx/queries/submissions/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter', 'offset', 'sort', 'ids', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconSubmissionQuota {
    [CmdletBinding(DefaultParameterSetName = '/falconx/queries/submissions/v1:get')]
    param()
    begin {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/falconx/queries/submissions/v1?limit=1"
            Method  = 'get'
            Headers = @{
                Accept = 'application/json'
            }
        }
    }
    process {
        $Request = $Script:Falcon.Api.Invoke($Param)
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta.quota
        } else {
            throw "Unable to retrieve submission quota. Check client permissions."
        }
    }
}
function New-FalconSubmission {
    [CmdletBinding(DefaultParameterSetName = '/falconx/entities/submissions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('android', 'ubuntu16_x64', 'win7_x64', 'win7_x86', 'win10_x64')]
        [string] $EnvironmentId,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 2)]
        [ValidatePattern('^\w{64}$')]
        [string] $Sha256,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 3)]
        [string] $Url,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 4)]
        [string] $SubmitName,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 5)]
        [ValidateSet('default', 'default_maxantievasion', 'default_randomfiles', 'default_randomtheme',
            'default_openie')]
        [string] $ActionScript,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 6)]
        [string] $CommandLine,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 7)]
        [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
        [string] $SystemDate,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 8)]
        [ValidatePattern('^\d{2}:\d{2}$')]
        [string] $SystemTime,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 9)]
        [string] $DocumentPassword,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 10)]
        [ValidateSet('default', 'tor', 'simulated', 'offline')]
        [string] $NetworkSettings,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 11)]
        [boolean] $EnableTor,

        [Parameter(ParameterSetName = '/falconx/entities/submissions/v1:post', Position = 12)]
        [array] $UserTags
    )
    begin {
        $Fields = @{
            ActionScript     = 'action_script'
            CommandLine      = 'command_line'
            DocumentPassword = 'document_password'
            EnableTor        = 'enable_tor'
            EnvironmentId    = 'environment_id'
            NetworkSettings  = 'network_settings'
            SubmitName       = 'submit_name'
            SystemDate       = 'system_date'
            SystemTime       = 'system_time'
            UserTags         = 'user_tags'
        }
        $PSBoundParameters.EnvironmentId = switch ($PSBoundParameters.EnvironmentId) {
            'android'      { 200 }
            'ubuntu16_x64' { 300 }
            'win7_x64'     { 110 }
            'win7_x86'     { 100 }
            'win10_x64'    { 160 }
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root    = @('user_tags')
                    sandbox = @('submit_name', 'system_date', 'action_script', 'environment_id', 'command_line',
                        'system_time', 'url', 'document_password', 'enable_tor', 'sha256', 'network_settings')
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
            throw "Url and Sha256 cannot be combined in a submission."
        } else {
            Invoke-Falcon @Param
        }
    }
}
function Receive-FalconArtifact {
    [CmdletBinding(DefaultParameterSetName = '/falconx/entities/artifacts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falconx/entities/artifacts/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/falconx/entities/artifacts/v1:get', Mandatory = $true, Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Query = @('name', 'id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconReport {
    [CmdletBinding(DefaultParameterSetName = '/falconx/entities/reports/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/falconx/entities/reports/v1:delete', Mandatory = $true, Position = 1)]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}