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
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(DefaultParameterSetName='/reports:get',SupportsShouldProcess)]
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
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(DefaultParameterSetName='/images/{id}:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/images/{id}:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [object]$Id
    )
    begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; HostUrl = Get-ContainerUrl }}
    process {
        $PSBoundParameters.Id = switch ($PSBoundParameters.Id) {
            { $_.ImageInfo.id } { $_.ImageInfo.id }
            { $_ -is [string] } { $_ }
        }
        if ($PSBoundParameters.Id -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "'$($PSBoundParameters.Id)' is not a valid image identifier."
        } else {
            $Endpoint = $PSCmdlet.ParameterSetName -replace '{id}',$PSBoundParameters.Id
            [void]$PSBoundParameters.Remove('Id')
            Invoke-Falcon @Param -Endpoint $Endpoint -Inputs $PSBoundParameters
        }
    }
}
function Request-FalconRegistryCredential {
<#
.SYNOPSIS
Request your Falcon container security image registry username and token
.DESCRIPTION
Requires 'Falcon Container Image: Read' and 'Sensor Download: Read'.

If successful, you token and username are cached for re-use as you use Falcon container security related commands.

If an active access token is due to expire in less than 15 seconds, a new token will automatically be requested.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-registry-credentials/v1:get',
        SupportsShouldProcess)]
    param()
    process {
        if (!$Script:Falcon.Registry.Token -or !$Script:Falcon.Registry.Expiration -lt (Get-Date).AddSeconds(15)) {
            [string]$Token = try {
                (Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName).Token
            } catch {
                throw "Failed to retrieve token. Verify 'Falcon Container Image: Read' permission."
            }
            if ($Token) {
                if (!$Script:Falcon.Registry) { $Script:Falcon['Registry'] = @{} }
                $Script:Falcon.Registry['Token'] = $Token
                $Script:Falcon.Registry['Expiration'] = (Get-Date).AddMinutes(30)
                if (!$Script:Falcon.Registry.Username) {
                    try {
                        $Script:Falcon.Registry['Username'] = 'fc',
                            (Get-FalconCcid -EA 0).Split('-')[0].ToLower() -join '-'
                    } catch {
                        throw "Failed to retrieve username. Verify 'Sensor Update Policies: Read' permission."
                    }
                }
            }
        }
    }
}
function Test-FalconRegistryCredential {
<#
.SYNOPSIS
Display Falcon container security image registry token and username
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon.Registry) {
            [PSCustomObject]@{
                Token = if ($Script:Falcon.Expiration -gt (Get-Date)) { $true } else { $false }
                Username = $Script:Falcon.Registry.Username
            }
        } else {
            Write-Error "No registry credential available. Try 'Request-FalconRegistryToken'."
        }
    }
}