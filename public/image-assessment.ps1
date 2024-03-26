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
    [Alias('packages')]
    [object[]]$Package,
    [Parameter(ParameterSetName='/image-assessment/combined/vulnerability-lookups/v1:post',Position=3)]
    [Alias('applicationPackages')]
    [object[]]$Application
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$PackList = @()
    [System.Collections.Generic.List[object]]$AppList = @()
  }
  process {
    if ($Package) {
      @($Package).foreach{
        # Filter to defined 'packages' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.packages
        $PackList.Add($i)
      }
    }
    if ($Application) {
      @($Application).foreach{
        # Filter to defined 'applicationPackages' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.applicationPackages
        $AppList.Add($i)
      }
    }
  }
  end {
    if ($PackList) {
      # Add 'packages' as an array and remove remaining value
      $PSBoundParameters['packages'] = @($PackList)
      [void]$PSBoundParameters.Remove('Package')
    }
    if ($AppList) {
      # Add 'packages' as an array and remove remaining value
      $PSBoundParameters['applicationPackages'] = @($AppList)
      [void]$PSBoundParameters.Remove('Application')
    }
    # Modify 'Format' to ensure 'packages' and 'applicationPackages' are properly appended and make request
    [void]$Param.Format.Body.Remove('packages')
    [void]$Param.Format.Body.Remove('applicationPackages')
    $Param.Format.Body.root += 'packages','applicationPackages'
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}