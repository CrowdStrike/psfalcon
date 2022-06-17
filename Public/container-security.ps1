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
function Get-FalconContainerSensor {
<#
.SYNOPSIS
Retrieve the most recent Falcon container sensor build tags
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER LatestUrl
Create a URL using the most recent build tag
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(DefaultParameterSetName='/v2/{sensortype}/{region}/release/falcon-sensor/tags/list:get',
        SupportsShouldProcess)]
    param(
        [switch]$LatestUrl
    )
    process {
        if (!$Script:Falcon.Registry -or $Script:Falcon.Registry.Expiration -lt (Get-Date).AddSeconds(60)) {
            Request-FalconRegistryCredential
        }
        $Param = @{
            Endpoint = $PSCmdlet.ParameterSetName -replace '{sensortype}',
                $Script:Falcon.Registry.SensorType -replace '{region}',$Script:Falcon.Registry.Region
            Header = @{ Authorization = "Bearer $($Script:Falcon.Registry.Token)" }
            HostUrl = Get-ContainerUrl -Registry
        }
        $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        $Result = try { $Request | ConvertFrom-Json } catch { $Request }
        if ($LatestUrl) {
            ($Param.HostUrl -replace 'https://',$null),$Script:Falcon.Registry.SensorType,
                $Script:Falcon.Registry.Region,'release',"falcon-sensor:$($Result.tags[-1])" -join '/'
        } else {
            $Result
        }
    }
}
function Remove-FalconContainerImage {
<#
.SYNOPSIS
Remove a Falcon container image
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
function Remove-FalconRegistryCredential {
<#
.SYNOPSIS
Remove your cached Falcon container registry access token and credential information from the module
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    process { if ($Script:Falcon.Registry) { [void]$Script:Falcon.Remove('Registry') }}
}
function Request-FalconRegistryCredential {
<#
.SYNOPSIS
Request your Falcon container registry username, password and access token
.DESCRIPTION
Requires 'Falcon Container Image: Read' and 'Sensor Download: Read'.

If successful, you token and username are cached for re-use as you use Falcon container security related commands.

If an active access token is due to expire in less than 15 seconds, a new token will automatically be requested.
.PARAMETER SensorType
Container sensor type, used to determine container registry
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory,Position=1)]
        [ValidateSet('falcon-sensor','falcon-container',IgnoreCase=$false)]
        [string]$SensorType
    )
    process {
        [System.Collections.Hashtable]$Credential = @{}
        $Credential['Username'] = if ($Script:Falcon.Registry.Username) {
            $Script:Falcon.Registry.Username
        } else {
            try {
                @(Get-FalconCcid -EA 0).foreach{ 'fc',$_.Split('-')[0].ToLower() -join '-' }
            } catch {
                throw "Failed to retrieve registry username. Verify 'Sensor Download: Read' permission."
            }
        }
        $Credential['Password'] = if ($Script:Falcon.Registry.Password) {
            $Script:Falcon.Registry.Password
        } else {
            try {
                (Invoke-Falcon -Endpoint (
                    '/container-security/entities/image-registry-credentials/v1:get')).Token
            } catch {
                throw "Failed to retrieve registry password. Verify 'Falcon Container Image: Read' permission."
            }
        }
        if ($Credential.Username -and $Credential.Password) {
            $Param = @{
                Endpoint = "/v2/token?=$($Credential.Username):get"
                Header = @{
                    Authorization = "Basic $([System.Convert]::ToBase64String(
                        [System.Text.Encoding]::ASCII.GetBytes("$($Credential.Username):$(
                            $Credential.Password)")))"
                }
                Format = @{ Query = @('scope','service') }
                HostUrl = Get-ContainerUrl -Registry
            }
            [string]$Region = switch -Regex ($Script:Falcon.Hostname) {
                'eu-1'        { 'eu-1' }
                'laggar\.gcw' { 'us-gov-1' }
                'us-2'        { 'us-2' }
                default       { 'us-1' }
            }
            $PSBoundParameters['scope'] = 'repository:',"/$Region/release/",':pull' -join
                $PSBoundParameters.SensorType
            $PSBoundParameters['service'] = 'registry.crowdstrike.com'
            [void]$PSBoundParameters.Remove('SensorType')
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
            if ($Request) {
                $Script:Falcon['Registry'] = @{
                    Username = $Credential.Username
                    Password = $Credential.Password
                    Region = $Region
                    SensorType = $SensorType
                    Token = $Request.token
                    Expiration = (Get-Date).AddSeconds($Request.expires_in)
                }
            }
        }
    }
}
function Show-FalconRegistryCredential {
<#
.SYNOPSIS
Display Falcon container registry credential information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon.Registry) {
            [string]$PullToken = if ($Script:Falcon.Registry.Username -and $Script:Falcon.Registry.Password) {
                [string]$BaseAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$(
                    $Script:Falcon.Registry.Username):$($Script:Falcon.Registry.Password)"))
                [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$([PSCustomObject]@{
                    auths = @{ 'registry.crowdstrike.com' = @{ auth = $BaseAuth }}} | ConvertTo-Json -Depth 4)"))
            }
            [PSCustomObject]@{
                Token = if ($Script:Falcon.Registry.Token -and $Script:Falcon.Registry.Expiration -gt
                (Get-Date).AddSeconds(60)) {
                    $true
                } else {
                    $false
                }
                Username = $Script:Falcon.Registry.Username
                Password = $Script:Falcon.Registry.Password
                Region = $Script:Falcon.Registry.Region
                SensorType = $Script:Falcon.Registry.SensorType
                PullToken = $PullToken
                Expiration = $Script:Falcon.Expiration
            }
        } else {
            Write-Error "No registry credential available. Try 'Request-FalconRegistryCredential'."
        }
    }
}