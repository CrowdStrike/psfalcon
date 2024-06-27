[string[]]$ExcludeCountType = 'find-by-runtimeversion'
function Edit-FalconContainerPolicy {
<#
.SYNOPSIS
Update Image Assessment Policy entities
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Id
Image assessment policy identifier
.PARAMETER Description

.PARAMETER IsEnabled

.PARAMETER Name

.PARAMETER PolicyData

.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconContainerPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [string]$Id,
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',Mandatory,
      Position=0)]
    [string]$Name,
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',Mandatory,
      Position=0)]
    [string]$Description,
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',Position=0)]
    [Alias('is_enabled')]
    [boolean]$IsEnabled,
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:patch',Position=0)]
    [Alias('policy_data')]
    [object]$PolicyData
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconContainerRegistry {
<#
.SYNOPSIS
Modify a registry within Falcon Cloud Security
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Name
Falcon Cloud Security registry name
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
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
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
function Get-FalconContainer {
<#
.SYNOPSIS
Search for containers in Falcon Cloud Security
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results

Search Kubernetes containers using a query in Falcon Query Language (FQL). Supported filters:
agent_id,agent_type,allow_privilege_escalation,cid,cloud_account_id,cloud_name,cloud_region,cluster_id,
cluster_name,container_id,container_name,cve_id,detection_name,first_seen,image_detection_count,image_digest,
image_has_been_assessed,image_id,image_registry,image_repository,image_tag,image_vulnerability_count,
insecure_mount_source,insecure_mount_type,insecure_propagation_mode,interactive_mode,ipv4,ipv6,labels,last_seen,
namespace,node_name,node_uid,package_name_version,pod_id,pod_name,port,privileged,root_write_access,
run_as_root_group,run_as_root_user,running_status
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainer
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/combined/containers/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/combined/containers/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
<#
function Get-FalconContainerAssessment {
#
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
#
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
#>
function Get-FalconContainerAssessment {
<#
.SYNOPSIS
Search for Falcon Container Security image assessment results
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results

Filter images using a query in Falcon Query Language (FQL). Supported filters:
container_id, container_running_status, cve_id, detection_name, detection_severity, first_seen, image_digest,
image_id, registry, repository, tag, vulnerability_severity
.PARAMETER Sort
Property and direction to sort results

The fields to sort the records on. Supported columns:
first_seen highest_detection_severity highest_vulnerability_severity image_digest image_id registry repository tag
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAssessment
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/combined/image-assessment/images/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/combined/image-assessment/images/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContainerCount {
<#
.SYNOPSIS
Return resource counts from Falcon Cloud Security
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Resource
Falcon Cloud Security resource to count [default: containers]
.PARAMETER Type
Retrieve specific counts by type [default: count]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerCount
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/aggregates/{resource}/{type}/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/aggregates/{resource}/{type}/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/aggregates/{resource}/{type}/v1:get',Position=2)]
    [string]$Resource,
    [Parameter(ParameterSetName='/container-security/aggregates/{resource}/{type}/v1:get',Position=3)]
    [string]$Type
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName } }
  process {
    if (!$PSBoundParameters.Resource) { $PSBoundParameters['Resource'] = 'containers' }
    if (!$PSBoundParameters.Type) { $PSBoundParameters['Type'] = 'count' }
    if ($Script:Falcon.Format) {
      # Determine valid 'Resource' and 'Type' values using 'Format.json'
      [string[]]$ValidResource = @($Script:Falcon.Format.PSObject.Properties.Name).Where({
        $_ -match '/container-security/aggregates/[\w-]+/[\w-]+/v1'
      }).foreach{
        @($_ -replace '(/container-security/aggregates/|/v1)',$null -split '/',2)[0]
      } | Select-Object -Unique | Sort-Object
      if ($ValidResource -and $ValidResource -notcontains $PSBoundParameters.Resource) {
        # Error if 'Resource' is not in ValidResource list
        throw 'Invalid "Resource" value. [Accepted: {1}]' -f $PSBoundParameters.Resource,
          ($ValidResource -join ', ')
      }
      [string[]]$ValidType = @($Script:Falcon.Format.PSObject.Properties.Name).Where({
        $_ -match ('/container-security/aggregates/{0}/[\w-]+/v1' -f $PSBoundParameters.Resource)
      }).foreach{
        @($_ -replace '(/container-security/aggregates/|/v1)',$null -split '/',2)[1]
      } | Where-Object { $ExcludeCountType -notcontains $_ } | Sort-Object
      if ($ValidType -and $ValidType -notcontains $PSBoundParameters.Type) {
        # Error if 'Type' is not in ValidType list
        throw 'Invalid "Type" value for "{0}". [Accepted: {1}]' -f $PSBoundParameters.Resource,
          ($ValidType -join ', ')
      }
    }
    @('resource','type').foreach{
      # Update target API endpoint using 'Resource' and 'Type'
      $Param.Endpoint = $Param.Endpoint -replace "{$_}",$PSBoundParameters.$_
      [void]$PSBoundParameters.Remove($_)
    }
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    if ($Request -and $Request.buckets) {
      # Output 'buckets' sub-object
      $Request.buckets
    } elseif ($Request -and $null -ne $Request.count) {
      # Output 'count' sub-object
      $Request.count
    } else {
      # Output entire result when 'buckets' or 'count' were not provided
      $Request
    }
  }
}
function Get-FalconContainerDetection {
<#
.SYNOPSIS
Search for Falcon Cloud Security image assessment detections
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerDetection
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/queries/detections/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/combined/detections/v1:get',Position=1)]
    [Parameter(ParameterSetName='/container-security/queries/detections/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/detections/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/detections/v1:get',Position=3)]
    [Parameter(ParameterSetName='/container-security/queries/detections/v1:get',Position=2)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/detections/v1:get')]
    [Parameter(ParameterSetName='/container-security/queries/detections/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/detections/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/container-security/queries/detections/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/queries/detections/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContainerDriftIndicator {
<#
.SYNOPSIS
Retrieve all drift indicators that match the given query
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Id
Falcon Cloud Security drift indicator
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerDriftIndicator
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/queries/drift-indicators/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/drift-indicators/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/container-security/combined/drift-indicators/v1:get',Position=1)]
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/drift-indicators/v1:get',Position=2)]
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/drift-indicators/v1:get',Position=3)]
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/drift-indicators/v1:get')]
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/drift-indicators/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/queries/drift-indicators/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerIom {
<#
.SYNOPSIS
Search for Falcon Container Security Kubernetes Indicators of Misconfiguration
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Id
Falcon Cloud Security Kubernetes IOM identifier
.PARAMETER Filter
Falcon Query Language expression to limit results

Search Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filters:
cid,cis_id,cluster_id,cluster_name,containers_impacted_count,containers_impacted_ids,detection_type,name,namespace,
prevented,resource_id,resource_name,resource_type,severity
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerIom
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/queries/kubernetes-ioms/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/kubernetes-ioms/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/container-security/combined/kubernetes-ioms/v1:get',Position=1)]
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/kubernetes-ioms/v1:get',Position=2)]
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/kubernetes-ioms/v1:get',Position=3)]
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/kubernetes-ioms/v1:get')]
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/kubernetes-ioms/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/queries/kubernetes-ioms/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerPolicy {
<#
.SYNOPSIS
Get all Image Assessment policies
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-assessment-policies/v1:get',
    SupportsShouldProcess)]
  param()
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContainerRegistry {
<#
.SYNOPSIS
List Falcon Cloud Security registries
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
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
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
    if (!$Script:Falcon.Registry -or $Script:Falcon.Registry.Expiration -lt (Get-Date).AddSeconds(240)) {
      Request-FalconRegistryCredential
    }
    if ($Script:Falcon.Registry) {
      $Param = @{
        Command = $MyInvocation.MyCommand.Name
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
}
function Get-FalconContainerVulnerability {
<#
.SYNOPSIS
Search for Falcon Cloud Security container image vulnerabilities
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.PARAMETER Id
CVE identifier
.PARAMETER Filter
Falcon Query Language expression to limit results

Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filters:
base_os,cid,container_id,container_running_status,containers_impacted_range,cps_rating,cve_id,cvss_score,
description,exploited_status,exploited_status_name,fix_status,image_digest,image_id,images_impacted_range,
package_name_version,registry,repository,severity,tag
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Sort
Property and direction to sort results

The fields to sort the records on. Supported columns:
cps_current_rating cve_id cvss_score description images_impacted packages_impacted severity
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerVulnerability
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/combined/vulnerabilities/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/info/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory)]
    [Alias('cve_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/container-security/combined/vulnerabilities/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconContainerPolicy {
<#
.SYNOPSIS
Create Image Assessment policies
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Name

.PARAMETER Description

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContainerPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-assessment-policies/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:post',Mandatory,
      Position=0)]
    [string]$Name,
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:post',Mandatory,
      Position=0)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconContainerRegistry {
<#
.SYNOPSIS
Create a registry within Falcon Cloud Security
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Name
Desired registry name within Falcon Cloud Security
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
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/registries/v1:post',SupportsShouldProcess)]
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
function Remove-FalconContainerPolicy {
<#
.SYNOPSIS
Delete Image Assessment Policy by policy UUID
.DESCRIPTION
Requires 'Falcon Container Image: Write'.
.PARAMETER Id
Image assessment policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContainerPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-assessment-policies/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/container-security/entities/image-assessment-policies/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconContainerRegistry {
<#
.SYNOPSIS
Remove a registry from Falcon Cloud Security
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
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
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
If successful, you token and username are cached for re-use as you use Falcon Cloud Security related commands.

If an active access token is due to expire in less than 4 minutes, a new token will automatically be requested.

Requires 'Falcon Container Image: Read' and 'Sensor Download: Read'.
.PARAMETER SensorType
Container sensor type, used to determine container registry
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Request-FalconRegistryCredential
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Position=1)]
    [ValidateSet('falcon-sensor','falcon-container',IgnoreCase=$false)]
    [string]$SensorType
  )
  process {
    [System.Collections.Hashtable]$Credential = @{
      Username = if ($Script:Falcon.Registry.Username) {
        $Script:Falcon.Registry.Username
      } else {
        try {
          @(Get-FalconCcid -EA 0).foreach{ 'fc',$_.Split('-')[0].ToLower() -join '-' }
        } catch {
          throw "Failed to retrieve registry username. Verify 'Sensor Download: Read' permission."
        }
      }
      Password = if ($Script:Falcon.Registry.Password) {
        $Script:Falcon.Registry.Password
      } else {
        try {
          (Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint (
            '/container-security/entities/image-registry-credentials/v1:get')).Token
        } catch {
          throw "Failed to retrieve registry password. Verify 'Falcon Container Image: Read' permission."
        }
      }
    }
    if ($Credential.Username -and $Credential.Password) {
      $Param = @{
        Command = $MyInvocation.MyCommand.Name
        Endpoint = "/v2/token?=$($Credential.Username):get"
        Header = @{
          Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(
            "$($Credential.Username):$($Credential.Password)")))"
        }
        Format = @{ Query = @('scope','service') }
        HostUrl = Get-ContainerUrl -Registry
      }
      [string]$Region = switch -Regex ($Script:Falcon.Hostname) {
        'eu-1' { 'eu-1' }
        'laggar\.gcw' { 'us-gov-1' }
        'us-2' { 'us-2' }
        default { 'us-1' }
      }
      $SensorType = if ($PSBoundParameters.SensorType) {
        $PSBoundParameters.SensorType
      } elseif ($Script:Falcon.Registry.SensorType) {
        $Script:Falcon.Registry.SensorType
      } else {
        Read-Host 'SensorType'
      }
      $PSBoundParameters['scope'] = 'repository:',"/$Region/release/",':pull' -join $SensorType
      $PSBoundParameters['service'] = 'registry.crowdstrike.com'
      [void]$PSBoundParameters.Remove('SensorType')
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
      @('token','expires_in').foreach{
        if (!$Request.$_) { throw "Token request failed. Missing expected '$_' property from response." }
      }
      if ($Request.token -and $Request.expires_in) {
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
          (Get-Date).AddSeconds(240)) { $true } else { $false }
        Username = $Script:Falcon.Registry.Username
        Password = $Script:Falcon.Registry.Password
        Region = $Script:Falcon.Registry.Region
        SensorType = $Script:Falcon.Registry.SensorType
        PullToken = $PullToken
      }
    } else {
      throw "No registry credential available. Try 'Request-FalconRegistryCredential'."
    }
  }
}
Register-ArgumentCompleter -CommandName Get-FalconContainerCount -ParameterName Resource -ScriptBlock {
  if ($Script:Falcon.Format) {
    # Add 'Resource' to Get-FalconContainerCount using 'format.json'
    @($Script:Falcon.Format.PSObject.Properties.Name).Where({
      $_ -match '/container-security/aggregates/[\w-]+/[\w-]+/v1'
    }).foreach{
      ($_ -replace '(/container-security/aggregates/|/v1)',$null -split '/',2)[0]
    } | Select-Object -Unique | Sort-Object
  }
}
Register-ArgumentCompleter -CommandName Get-FalconContainerCount -ParameterName Type -ScriptBlock {
  if ($Script:Falcon.Format) {
    # Add 'Type' to Get-FalconContainerCount using 'Format.json'
    @($Script:Falcon.Format.PSObject.Properties.Name).Where({
      $_ -match '/container-security/aggregates/[\w-]+/[\w-]+/v1'
    }).foreach{
      ($_ -replace '(/container-security/aggregates/|/v1)',$null -split '/',2)[1]
    } | Select-Object -Unique | Where-Object { $ExcludeCountType -notcontains $_ } | Sort-Object
  }
}