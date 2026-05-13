function Get-FalconCloudFrameworkSummary {
<#
.SYNOPSIS
Retrieve Falcon Cloud Security compliance framework summaries
.DESCRIPTION
Requires 'Cloud Security API Assets: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Id
Compliance framework identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudFrameworkSummary
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-security-compliance/entities/framework-posture-summaries/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-security-compliance/entities/framework-posture-summaries/v1:get',
      Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-security-compliance/entities/framework-posture-summaries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids') }
      Max = 20
    }
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
function Get-FalconCloudRuleSummary {
<#
.SYNOPSIS
Retrieve Falcon Cloud Security compliance rule summaries
.DESCRIPTION
Requires 'Cloud Security API Assets: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Id
Compliance rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudRuleSummary
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-security-compliance/entities/rule-posture-summaries/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-security-compliance/entities/rule-posture-summaries/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-security-compliance/entities/rule-posture-summaries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids') }
      Max = 300
    }
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