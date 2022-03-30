function Get-FalconReport {
<#
.SYNOPSIS
Search for Falcon X Sandbox reports
.DESCRIPTION
Requires 'Sandbox (Falcon X): Read'.
.PARAMETER Id
Report identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Summary
Return a summary version
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/queries/reports/v1:get')]
    param(
        [Parameter(ParameterSetName='/falconx/entities/reports/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/falconx/entities/report-summaries/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=2)]
        [string]$Sort,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=3)]
        [ValidateRange(1,5000)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=4)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/falconx/entities/report-summaries/v1:get',Mandatory)]
        [switch]$Summary,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','offset','sort','ids','limit') }
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
function Get-FalconSubmission {
<#
.SYNOPSIS
Search for Falcon X Sandbox submissions
.DESCRIPTION
Requires 'Sandbox (Falcon X): Read'.
.PARAMETER Id
Submission identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/queries/submissions/v1:get')]
    param(
        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=2)]
        [string]$Sort,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=3)]
        [ValidateRange(1,5000)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=4)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','offset','sort','ids','limit') }
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
function Get-FalconSubmissionQuota {
<#
.SYNOPSIS
Retrieve monthly Falcon X Sandbox submission quota
.DESCRIPTION
Requires 'Sandbox (Falcon X): Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/queries/submissions/v1:get')]
    param()
    process {
        $Request = Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName -RawOutput -EA 0
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta.quota
        } else {
            throw "Unable to retrieve submission quota. Check client permissions."
        }
    }
}
function New-FalconSubmission {
<#
.SYNOPSIS
Submit a sample to the Falcon X Sandbox
.DESCRIPTION
Requires 'Sandbox (Falcon X): Write'.

'Sha256' values are retrieved from files that are uploaded using 'Send-FalconSample'. Files must be uploaded
before they can be provided to the Falcon X Sandbox.
.PARAMETER EnvironmentId
Analysis environment
.PARAMETER Sha256
Sha256 hash value
.PARAMETER Url
A webpage or file URL
.PARAMETER SubmitName
Submission name
.PARAMETER ActionScript
Runtime script for sandbox analysis
.PARAMETER CommandLine
Command line script passed to the submitted file at runtime
.PARAMETER SystemDate
A custom date to use in the analysis environment
.PARAMETER SystemTime
A custom time to use in the analysis environment
.PARAMETER DocumentPassword
Auto-filled for Adobe or Office files that prompt for a password
.PARAMETER NetworkSetting
Network settings to use in the analysis environment
.PARAMETER EnableTor
Route traffic via TOR
.PARAMETER UserTag
Tags to categorize the submission
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/entities/submissions/v1:post')]
    param(
        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Mandatory,Position=1)]
        [ValidateSet('android','ubuntu16_x64','win7_x64','win7_x86','win10_x64',IgnoreCase=$false)]
        [Alias('environment_id')]
        [string]$EnvironmentId,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=2)]
        [ValidatePattern('^\w{64}$')]
        [string]$Sha256,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=3)]
        [string]$Url,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=4)]
        [Alias('submit_name')]
        [string]$SubmitName,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=5)]
        [ValidateSet('default','default_maxantievasion','default_randomfiles','default_randomtheme',
            'default_openie',IgnoreCase=$false)]
        [Alias('action_script')]
        [string]$ActionScript,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=6)]
        [Alias('command_line')]
        [string]$CommandLine,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=7)]
        [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
        [Alias('system_date')]
        [string]$SystemDate,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=8)]
        [ValidatePattern('^\d{2}:\d{2}$')]
        [Alias('system_time')]
        [string]$SystemTime,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=9)]
        [Alias('document_password')]
        [string]$DocumentPassword,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=10)]
        [ValidateSet('default','tor','simulated','offline',IgnoreCase=$false)]
        [Alias('network_settings','NetworkSettings')]
        [string]$NetworkSetting,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=11)]
        [Alias('enable_tor')]
        [boolean]$EnableTor,

        [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=12)]
        [Alias('user_tags','UserTags')]
        [string[]]$UserTag
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('user_tags')
                    sandbox = @('submit_name','system_date','action_script','environment_id',
                        'command_line','system_time','url','document_password','enable_tor','sha256',
                        'network_settings')
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
            throw "'Url' and 'Sha256' can not be combined in a submission."
        } else {
            $PSBoundParameters.EnvironmentId = switch ($PSBoundParameters.EnvironmentId) {
                'android'      { 200 }
                'ubuntu16_x64' { 300 }
                'win7_x64'     { 110 }
                'win7_x86'     { 100 }
                'win10_x64'    { 160 }
            }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Receive-FalconArtifact {
<#
.SYNOPSIS
Download an artifact from a Falcon X Sandbox report
.DESCRIPTION
Requires 'Sandbox (Falcon X): Read'.

Artifact identifier values can be retrieved for specific Falcon X Sandbox reports using 'Get-FalconReport'.
.PARAMETER Path
Destination path
.PARAMETER Id
Artifact identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/entities/artifacts/v1:get')]
    param(
        [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get',Mandatory,Position=1)]
        [string]$Path,

        [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{64}$')]
        [string]$Id,

        [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{ Query = @('name','id') }
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
function Remove-FalconReport {
<#
.SYNOPSIS
Remove a Falcon X Sandbox report
.DESCRIPTION
Requires 'Sandbox (Falcon X): Write'.
.PARAMETER Id
Report identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X
#>
    [CmdletBinding(DefaultParameterSetName='/falconx/entities/reports/v1:delete')]
    param(
        [Parameter(ParameterSetName='/falconx/entities/reports/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Alias('ids')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}