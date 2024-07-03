function Get-FalconAsset {
<#
.SYNOPSIS
Search for assets in Falcon Discover
.DESCRIPTION
Requires 'Falcon Discover: Read' and 'Falcon Discover IoT: Read'.
.PARAMETER Id
Asset identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Include
Include additional properties
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.PARAMETER Account
Search for user account assets
.PARAMETER Application
Search for applications
.PARAMETER External
Search for external assets
.PARAMETER IoT
Search for IoT assets
.PARAMETER Login
Search for login events
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconAsset
#>
  [CmdletBinding(DefaultParameterSetName='/discover/queries/hosts/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/discover/entities/applications/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/discover/entities/hosts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/discover/entities/iot-hosts/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Position=1)]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get',Position=1)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=1)]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=1)]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=1)]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get',Position=1)]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=1)]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Position=2)]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get',Position=2)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=2)]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=2)]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=2)]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get',Position=2)]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=2)]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Position=3)]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get',Position=3)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=3)]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=3)]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=3)]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get',Position=3)]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=3)]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Position=4)]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get',Position=4)]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=4)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=4)]
    [ValidateSet('login_event','browser_extension','host_info','install_usage','system_insights','third_party',
      'risk_factors',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get')]
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get')]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get')]
    [string]$After,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get')]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get')]
    [Parameter(ParameterSetName='/discover/combined/hosts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get')]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get')]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get')]
    [switch]$Total,
    [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Mandatory)]
    [switch]$Account,
    [Parameter(ParameterSetName='/discover/combined/applications/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/entities/applications/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Mandatory)]
    [switch]$Application,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/fem/queries/external-assets/v1:get',Mandatory)]
    [switch]$External,
    [Parameter(ParameterSetName='/discover/entities/iot-hosts/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/queries/iot-hosts/v2:get',Mandatory)]
    [switch]$IoT,
    [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Mandatory)]
    [switch]$Login
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
    $RegEx = @{
      CombinedUrl = '/discover/combined/(applications|hosts)/v1:get'
      AppFacet = '^(browser_extension|host_info|install_usage)$'
      HostFacet = '^(login_event|system_insights|third_party|risk_factors)$'
    }
    if ($PSBoundParameters.All -and !$PSBoundParameters.Limit) {
      # Add appropriate 'Limit' when using 'All'
      $PSBoundParameters['Limit'] = if ($PSCmdlet.ParameterSetName -match $RegEx.CombinedUrl) { 1000 } else { 100 }
    }
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      # Submit 'id' values to /entities/ API in groups of 100
      $PSBoundParameters['Id'] = @($List)
      $Param['Max'] = 100
    } else {
      # Error when 'Limit' exceeds 100 or 1,000 for relevant API
      $MaxLimit = if ($PSCmdlet.ParameterSetName -match $RegEx.CombinedUrl) { 1000 } else { 100 }
      if ($PSBoundParameters.Limit -and $PSBoundParameters.Limit -gt $MaxLimit) {
        $Message = (('Cannot validate argument on parameter {0}. The {1} argument is greater than the maximum al' +
          'lowed range of {2}. Supply an argument that is less than or equal to {2} and then try the command aga' +
          'in.') -f "'Limit'",$PSBoundParameters.Limit,$MaxLimit)
        throw $Message
      }
      if ($PSBoundParameters.Include) {
        # Error if individual 'Include' value is not valid for target API
        [string[]]$Valid = if ($PSCmdlet.ParameterSetName -eq '/discover/combined/applications/v1:get') {
          $RegEx.AppFacet -replace '[\^\(\)\$]',$null -split '\|'
        } elseif ($PSCmdlet.ParameterSetName -eq '/discover/combined/hosts/v1:get') {
          $RegEx.HostFacet -replace '[\^\(\)\$]',$null -split '\|'
        } elseif ($PSCmdlet.ParameterSetName -match '/queries/') {
          'login_event'
        }
        [string[]]$Facet = @($PSBoundParameters.Include).foreach{
          $Message = (('Cannot validate argument on parameter {0}. The argument "{1}" does not belong to the set' +
            ' "{2}" specified by the ValidateSet attribute. Supply an argument that is in the set and then try t' +
            'he command again.') -f "'Include'",$_,($Valid -join ','))
          if ($Valid -notcontains $_) { throw $Message } elseif ($_ -ne 'login_event') { $_ }
        }
        if ($Facet) {
          # Move 'Include' values to 'facet' for /combined/ API(s)
          $PSBoundParameters['facet'] = $Facet
          $PSBoundParameters.Include = @($PSBoundParameters.Include).Where({$Facet -notcontains $_})
          if (!$PSBoundParameters.Include) { [void]$PSBoundParameters.Remove('Include') }
        }
      }
    }
    $Request = if ($Include -contains 'login_event' -and !$PSBoundParameters.Detailed -and !$Account) {
      $PSBoundParameters['Detailed'] = $true
      Invoke-Falcon @Param -UserInput $PSBoundParameters | Select-Object id,aid
    } elseif ($Detailed -and ($Account -or $External -or $IoT -or $Login)) {
      # Re-submit 'id' values to appropriate /entities/ API to retrieve detail
      [void]$PSBoundParameters.Remove('Detailed')
      $IdList = Invoke-Falcon @Param -UserInput $PSBoundParameters
      if ($IdList -and $Account) {
        $IdList | & $MyInvocation.MyCommand.Name -Account
      } elseif ($IdList -and $External) {
        $IdList | & $MyInvocation.MyCommand.Name -External
      } elseif ($IdList -and $IoT) {
        $IdList | & $MyInvocation.MyCommand.Name -IoT
      } elseif ($IdList -and $Login) {
        $IdList | & $MyInvocation.MyCommand.Name -Login
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
    if ($Request -and $PSBoundParameters.Include -and $PSBoundParameters.Include -contains 'login_event') {
      # Match 'login_event' results with $ReqId
      if (!$Request.id) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ id = $_ }}}
      [string]$ReqId = if ($PSCmdlet.ParameterSetName -match 'hosts') { 'aid' } else { 'id' }
      [string]$Property = if ($ReqId -eq 'aid') { 'aid' } else { 'account_id' }
      for ($i=0; $i -lt ($Request | Measure-Object).Count; $i+=100) {
        # In groups of 100, perform filtered search for login events
        [string[]]$Group = @(@($Request)[$i..($i+99)]).Where({![string]::IsNullOrEmpty($_.$ReqId)}).$ReqId
        Write-Host ($Group -join ',')
        [string[]]$Filter = @($Group).foreach{ $Property,"'$_'" -join ':' }
        $Content = & $MyInvocation.MyCommand.Name -Filter ($Filter -join ',') -Login -Detailed -All -EA 0
        foreach ($Value in $Group) {
          @($Request).Where({$_.$ReqId -eq $Value}).foreach{
            # Append matched login events using 'aid' or 'account_id'
            Set-Property $_ login_event @($Content).Where({$_.$Property -eq $Value})
          }
        }
      }
    }
    $Request
  }
}