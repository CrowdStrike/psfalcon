function Get-FalconContainerAssessment {
<#
.SYNOPSIS
Retrieve Falcon container image assessment reports
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Registry
Container registry
.PARAMETER Repository
Container repository
.PARAMETER Tag
Container tag
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Container-Upload
#>
    [CmdletBinding(DefaultParameterSetName='/reports:get')]
    param(
        [Parameter(ParameterSetName='/reports:get',Mandatory,Position=1)]
        [string]$Registry,
        [Parameter(ParameterSetName='/reports:get',Mandatory,Position=2)]
        [string]$Repository,
        [Parameter(ParameterSetName='/reports:get',Mandatory,Position=3)]
        [string]$Tag
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('registry','repository','tag') }
            HostUrl = Get-ContainerUrl
        }
    }
    process {
        $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        try { $Request | ConvertFrom-Json } catch { $Request }
    }
}

function Remove-FalconContainerImage {
<#
.SYNOPSIS
Remove Falcon container images
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Id
Container image identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Container-Upload
#>
    [CmdletBinding(DefaultParameterSetName='/images/{id}:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/images/{id}:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [object]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            HostUrl = Get-ContainerUrl
        }
    }
    process {
        $PSBoundParameters.Id = switch ($PSBoundParameters.Id) {
            { $_.ImageInfo.id } { $_.ImageInfo.id }
            { $_ -is [string] } { $_ }
        }
        if ($PSBoundParameters.Id -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "'$($PSBoundParameters.Id)' is not a valid image identifier."
        } elseif ($PSCmdlet.ShouldProcess($PSBoundParameters.Id)) {
            $Endpoint = $PSCmdlet.ParameterSetName -replace '{id}',$PSBoundParameters.Id
            [void]$PSBoundParameters.Remove('Id')
            Invoke-Falcon @Param -Endpoint $Endpoint -Inputs $PSBoundParameters
        }
    }
}