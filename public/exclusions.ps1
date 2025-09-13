function Edit-FalconCertificateExclusion {
<#
.SYNOPSIS
Modify a certificate-based Machine Learning exclusion
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER Description
Exclusion description
.PARAMETER Status
Exclusion status
.PARAMETER Certificate
Certificate detail ('issuer', 'serial', 'subject', 'thumbprint', 'valid_from', 'valid_to')
.PARAMETER AppliedGlobally
Apply to all hosts in environment
.PARAMETER MemberCid
Member CIDs, used when in a Flight Control environment
.PARAMETER GroupId
Host group identifier
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Status,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=4)]
    [object]$Certificate,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=5)]
    [Alias('applied_globally')]
    [boolean]$AppliedGlobally,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=6)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [Alias('children_cids')]
    [string[]]$MemberCid,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('host_groups')]
    [string[]]$GroupId,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=8)]
    [string]$Comment,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=9)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Certificate) {
      # Force required properties in 'certificate'
      $PSBoundParameters.Certificate = Select-CertificateProperty $PSBoundParameters.Certificate
    }
    if ($PSBoundParameters.MemberCid) {
      $PSBoundParameters.MemberCid = @($PSBoundParameters.MemberCid).foreach{ Confirm-CidValue $_ }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconCertificate {
<#
.SYNOPSIS
Retrieve certificate signing information for a file
.DESCRIPTION
Requires 'Machine Learning exclusions: Read'.
.PARAMETER Id
Certificate identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCertificate
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/certificates/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/certificates/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCertificateExclusion {
<#
.SYNOPSIS
Search for certificate-based Machine Learning exclusions
.DESCRIPTION
Requires 'Machine Learning exclusions: Read'.
.PARAMETER Id
Exclusion identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_on.asc','created_on.desc','modified_by.asc',
      'modified_by.desc','modified_on.asc','modified_on.desc','name.asc','name.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/exclusions/queries/cert-based-exclusions/v1:get')]
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
function New-FalconCertificateExclusion {
<#
.SYNOPSIS
Create a certificate-based Machine Learning exclusion
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER Description
Exclusion description
.PARAMETER Status
Exclusion status
.PARAMETER Certificate
Certificate detail ('issuer', 'serial', 'subject', 'thumbprint', 'valid_from', 'valid_to')
.PARAMETER AppliedGlobally
Apply to all hosts in environment
.PARAMETER MemberCid
Member CIDs, used when in a Flight Control environment
.PARAMETER GroupId
Host group identifier
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Status,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=4)]
    [object]$Certificate,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=5)]
    [Alias('applied_globally')]
    [boolean]$AppliedGlobally,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=6)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [Alias('children_cids')]
    [string[]]$MemberCid,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('host_groups')]
    [string[]]$GroupId,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=8)]
    [string]$Comment
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Certificate) {
      # Force required properties in 'certificate'
      $PSBoundParameters.Certificate = Select-CertificateProperty $PSBoundParameters.Certificate
    }
    if ($PSBoundParameters.MemberCid) {
      $PSBoundParameters.MemberCid = @($PSBoundParameters.MemberCid).foreach{ Confirm-CidValue $_ }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconCertificateExclusion {
<#
.SYNOPSIS
Remove certificate-based Machine Learning exclusions
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',Position=1)]
    [string]$Comment,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Alias('ids')]
    [string[]]$Id
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