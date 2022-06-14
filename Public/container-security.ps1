function Request-FalconRegistryToken {
<#
.SYNOPSIS
Request your Falcon Container Security image registry username and token
.DESCRIPTION
Requires 'Falcon Container Image: Read' and 'Sensor Update Policies: Read'.

If successful, you token and username are cached for re-use as you use Falcon Container Security related commands.

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
function Test-FalconRegistryToken {
<#
.SYNOPSIS
Display Falcon Container Security image registry token status
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
            Write-Error "No container registry token available. Try 'Request-FalconRegistryToken'."
        }
    }
}