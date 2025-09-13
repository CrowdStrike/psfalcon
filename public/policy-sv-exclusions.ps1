function Edit-FalconSvExclusion {
<#
.SYNOPSIS
Modify a Sensor Visibility exclusion
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER DescendantProcess
Apply to descendant processes
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconSvExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Value,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [Alias('groups','GroupIds')]
    [object[]]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('is_descendant_process')]
    [boolean]$DescendantProcess,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [string]$Comment,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSCmdlet.ShouldProcess('Edit-FalconSvExclusion','Test-GroupId')) {
      if ($PSBoundParameters.GroupId) {
        # Filter to 'id' if supplied with 'detailed' objects
        if ($PSBoundParameters.GroupId.id) { [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id }
        @($PSBoundParameters.GroupId).foreach{
          if ($_ -notmatch '^([a-fA-F0-9]{32}|all)$') { throw "'$_' is not a valid Host Group identifier." }
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconSvExclusion {
<#
.SYNOPSIS
Search for Sensor Visibility exclusions
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Read'.
.PARAMETER Id
Exclusion identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSvExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/sv-exclusions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=2)]
    [ValidateSet('applied_globally.asc','applied_globally.desc','created_by.asc','created_by.desc',
      'created_on.asc','created_on.desc','last_modified.asc','last_modified.desc','modified_by.asc',
      'modified_by.desc','value.asc','value.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/sv-exclusions/v1:get')]
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
function New-FalconSvExclusion {
<#
.SYNOPSIS
Create a Sensor Visibility exclusion
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Value
RegEx pattern value
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER DescendantProcess
Apply to descendant processes
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconSvExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Value,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('groups','GroupIds')]
    [object[]]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('is_descendant_process')]
    [boolean]$DescendantProcess,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [string]$Comment
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    # Filter to 'id' if supplied with 'detailed' objects
    if ($PSBoundParameters.GroupId.id) { [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id }
    if ($PSBoundParameters.GroupId) {
      @($PSBoundParameters.GroupId).foreach{
        if ($_ -notmatch '^([a-fA-F0-9]{32}|all)$') { throw "'$_' is not a valid Host Group identifier." }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconSvExclusion {
<#
.SYNOPSIS
Remove Sensor Visibility exclusions
.DESCRIPTION
Requires 'Sensor Visibility Exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSvExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sv-exclusions/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Position=1)]
    [string]$Comment,
    [Parameter(ParameterSetName='/policy/entities/sv-exclusions/v1:delete',Mandatory,
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