function Edit-FalconContainerRegistry {
<#
.SYNOPSIS
Modify a registry within Falcon Container Security
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Name
Falcon Container Security registry name
.PARAMETER State
Registry connection state
.PARAMETER Credential
A hashtable containing credentials to access the registry
.PARAMETER Id
Container registry identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconContainerRegistry
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/registries/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:patch',Position=1)]
    [Alias('user_defined_alias')]
    [string]$Name,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:patch',Position=2)]
    [ValidateSet('pause','resume',IgnoreCase=$false)]
    [string]$State,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:patch',Position=3)]
    [hashtable]$Credential,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('credential','user_defined_alias','state') }
        Query = @('id')
      }
    }
  }
  process {
    if ($PSBoundParameters.Credential) {
      $PSBoundParameters.Credential = @{ details = $PSBoundParameters.Credential }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAssessment
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
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    try { $Request | ConvertFrom-Json } catch { $Request }
  }
}
function Get-FalconContainerRegistry {
<#
.SYNOPSIS
List Falcon Container Security registries
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Id
Container registry identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerRegistry
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/queries/registries/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get',Position=1)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get',Position=2)]
    [int]$Limit,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/queries/registries/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('offset','sort','limit','ids') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerSensor
#>
  [CmdletBinding(DefaultParameterSetName='/v2/{sensortype}/{region}/release/falcon-sensor/tags/list:get',
    SupportsShouldProcess)]
  param([switch]$LatestUrl)
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
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    $Result = try { $Request | ConvertFrom-Json } catch { $Request }
    if ($LatestUrl) {
      ($Param.HostUrl -replace 'https://',$null),$Script:Falcon.Registry.SensorType,
        $Script:Falcon.Registry.Region,'release',"falcon-sensor:$($Result.tags[-1])" -join '/'
    } else {
      $Result
    }
  }
}
function New-FalconContainerRegistry {
<#
.SYNOPSIS
Create a registry within Falcon Container Security
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Name
Desired registry name within Falcon Container Security
.PARAMETER Type
Registry type
.PARAMETER Url
URL used to log in to the registry
.PARAMETER Credential
A hashtable containing credentials to access the registry
.PARAMETER UrlUniquenessKey
Registry URL alias

Available with Docker Hub, Google Artifact Registry, Google Container Registry, IBM Cloud, and Oracle
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContainerRegistry
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/registries/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:post',Mandatory,Position=1)]
    [Alias('user_defined_alias')]
    [string]$Name,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:post',Mandatory,Position=2)]
    [ValidateSet('acr','artifactory','docker','dockerhub','ecr','gar','gcr','github','gitlab','harbor','icr',
      'mirantis','nexus','openshift','oracle','quay.io',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:post',Mandatory,Position=3)]
    [string]$Url,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:post',Mandatory,Position=4)]
    [hashtable]$Credential,
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:post',Position=5)]
    [Alias('url_uniqueness_key')]
    [string]$UrlUniquenessKey
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('credential','user_defined_alias','url','url_uniqueness_key','type') }}
    }
  }
  process {
    $PSBoundParameters.Credential = @{ details = $PSBoundParameters.Credential }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContainerImage
#>
  [CmdletBinding(DefaultParameterSetName='/images/{id}:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/images/{id}:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
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
      Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconContainerRegistry {
<#
.SYNOPSIS
Remove a registry from Falcon Container Security
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Id
Container registry identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContainerRegistry
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/registries/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/registries/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconRegistryCredential {
<#
.SYNOPSIS
Remove your cached Falcon container registry access token and credential information from the module
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconRegistryCredential
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
If successful, you token and username are cached for re-use as you use Falcon container security related commands.

If an active access token is due to expire in less than 15 seconds, a new token will automatically be requested.

Requires 'Falcon Container Image: Read' and 'Sensor Download: Read'.
.PARAMETER SensorType
Container sensor type, used to determine container registry
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Request-FalconRegistryCredential
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
        'eu-1'    { 'eu-1' }
        'laggar\.gcw' { 'us-gov-1' }
        'us-2'    { 'us-2' }
        default     { 'us-1' }
      }
      $PSBoundParameters['scope'] = 'repository:',"/$Region/release/",':pull' -join
        $PSBoundParameters.SensorType
      $PSBoundParameters['service'] = 'registry.crowdstrike.com'
      [void]$PSBoundParameters.Remove('SensorType')
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconRegistryCredential
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
      }
    } else {
      Write-Error "No registry credential available. Try 'Request-FalconRegistryCredential'."
    }
  }
}