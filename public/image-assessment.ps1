function Get-FalconContainerVulnerability {
<#
.SYNOPSIS
Retrieve known vulnerabilities for the provided image
.DESCRIPTION
Requires 'Falcon Container CLI: Write'.
.PARAMETER OsVersion
Operating system version
.PARAMETER Package
Key and value pairs to filter packages. Accepted properties include: 'layerhash', 'layerindex', 'majorversion',
'packagehash', 'packageprovider', 'packagesource', 'product', 'softwarearchitecture', 'status', and 'vendor'.
.PARAMETER Application
Key and value pairs to filter application packages. Accepted properties include: 'libraries' and 'type'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerVulnerability
#>
  [CmdletBinding(DefaultParameterSetName='/image-assessment/combined/vulnerability-lookups/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/image-assessment/combined/vulnerability-lookups/v1:post',Position=1)]
    [string]$OsVersion,
    [Parameter(ParameterSetName='/image-assessment/combined/vulnerability-lookups/v1:post',Position=2)]
    [ValidateScript({
      foreach ($Object in $_) {
        $Param = @{
          Object = $Object
          Command = 'Get-FalconContainerVulnerability'
          Endpoint = '/image-assessment/combined/vulnerability-lookups/v1:post'
          Allowed = @('layerindex','packageprovider','layerhash','packagehash','packagesource',
            'softwarearchitecture','status','majorversion','product','vendor')
        }
        Confirm-Parameter @Param
      }
    })]
    [Alias('packages')]
    [object[]]$Package,
    [Parameter(ParameterSetName='/image-assessment/combined/vulnerability-lookups/v1:post',Position=3)]
    [ValidateScript({
      foreach ($Object in $_) {
        $Param = @{
          Object = $Object
          Command = 'Get-FalconContainerVulnerability'
          Endpoint = '/image-assessment/combined/vulnerability-lookups/v1:post'
          Allowed = @('libraries','type')
        }
        Confirm-Parameter @Param
      }
    })]
    [Alias('applicationPackages')]
    [object[]]$Application
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('osversion','packages','applicationPackages') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}