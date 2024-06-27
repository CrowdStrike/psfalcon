function Edit-FalconCertificateExclusion {
<#
.SYNOPSIS
Updates existing Certificate Based Exclusions
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER AppliedGlobally

.PARAMETER Certificate

.PARAMETER ChildrenCid

.PARAMETER Comment
Audit log comment
.PARAMETER CreatedBy

.PARAMETER CreatedOn

.PARAMETER Description

.PARAMETER HostGroup

.PARAMETER Id
XXX identifier
.PARAMETER ModifiedBy

.PARAMETER ModifiedOn

.PARAMETER Name

.PARAMETER Status

.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [string]$Id,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('applied_globally')]
    [boolean]$AppliedGlobally,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [object]$Certificate,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('children_cids')]
    [string[]]$ChildrenCid,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [string]$Comment,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('created_by')]
    [string]$CreatedBy,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('created_on')]
    [datetime]$CreatedOn,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [string]$Description,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('host_groups')]
    [string[]]$HostGroup,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('modified_by')]
    [string]$ModifiedBy,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [Alias('modified_on')]
    [datetime]$ModifiedOn,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [string]$Name,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:patch',Position=0)]
    [string]$Status
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCertificate {
<#
.SYNOPSIS
Retrieves certificate signing information for a file
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
Search for certificate-based exclusions
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
    [ValidateScript({ Test-FqlStatement $_ })]
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
Create new Certificate Based Exclusions.
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER AppliedGlobally

.PARAMETER Certificate

.PARAMETER ChildrenCid

.PARAMETER Comment
Audit log comment
.PARAMETER CreatedBy

.PARAMETER CreatedOn

.PARAMETER Description

.PARAMETER HostGroups

.PARAMETER ModifiedBy

.PARAMETER ModifiedOn

.PARAMETER Name

.PARAMETER Status

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('applied_globally')]
    [boolean]$AppliedGlobally,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [object]$Certificate,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('children_cids')]
    [string[]]$ChildrenCid,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [string]$Comment,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('created_by')]
    [string]$CreatedBy,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('created_on')]
    [datetime]$CreatedOn,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [string]$Description,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('host_groups')]
    [string[]]$HostGroups,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('modified_by')]
    [string]$ModifiedBy,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [Alias('modified_on')]
    [datetime]$ModifiedOn,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Mandatory,Position=0)]
    [string]$Name,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:post',Position=0)]
    [string]$Status
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconCertificateExclusion {
<#
.SYNOPSIS
Delete the exclusions by id
.DESCRIPTION
Requires 'Machine Learning exclusions: Write'.
.PARAMETER Id
Exclusion identifier
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCertificateExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/exclusions/entities/cert-based-exclusions/v1:delete',Position=0)]
    [string]$Comment
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