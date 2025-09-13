function ConvertTo-FalconIoaExclusion {
<#
.SYNOPSIS
Output required fields to create an Indicator of Attack exclusion from a Falcon alert or detection
.DESCRIPTION
Uses the 'behaviors' of a detection, or specific properties of an alert to create a new Indicator of Attack
exclusion. Specfically, it maps the following properties these fields:

behavior_id/pattern_id > pattern_id
display_name > pattern_name
cmdline > cl_regex
filepath > ifn_regex
device.groups > groups

The 'cl_regex' and 'ifn_regex' fields are escaped using the [regex]::Escape() PowerShell accelerator. The
'ifn_regex' output also replaces the NT device path ('Device/HarddiskVolume') with a wildcard. If the host
involved in the alert/detection is not in any host groups, the resulting exclusion will apply to all host groups.

The output of this command can be passed to 'New-FalconIoaExclusion' to create an exclusion.
.PARAMETER Detection
Falcon alert or detection
.LINK
https://github.com/crowdstrike/psfalcon/wiki/ConvertTo-FalconIoaExclusion
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,ValueFromPipeline,Position=1)]
    [object]$Detection
  )
  begin {
    function New-ExObj ([object]$Obj,[string]$String) {
      if ($Obj.tactic -notmatch '^(Machine Learning|Malware)$') {
        [PSCustomObject]@{
          name = $Obj.display_name
          description = 'Created from {0} by {1}' -f $String,(Show-FalconModule).UserAgent
          pattern_id = if ($Obj.behavior_id) { $Obj.behavior_id } else { $Obj.pattern_id }
          pattern_name = $Obj.display_name
          cl_regex = [regex]::Escape($Obj.cmdline) -replace '(\\ {1,})+','\s+'
          ifn_regex = [regex]::Escape($Obj.filepath) -replace '\\\\Device\\\\HarddiskVolume\d+','.*'
          groups = if ($Obj.device.groups) { $Obj.device.groups } else { 'all' }
        }
      }
    }
    [System.Collections.Generic.List[PSCustomObject]]$Output = @()
  }
  process {
    if ($Detection.id) {
      # Convert 'alert'
      $Output.Add((New-ExObj $Detection $Detection.id))
    } elseif ($Detection.detection_id -and $Detection.behaviors) {
      # Convert 'detection' behaviors
      @($Detection.behaviors).foreach{ $Output.Add((New-ExObj $_ $Detection.detection_id)) }
    }
  }
  end { if ($Output) { @($Output | Group-Object value).foreach{ $_.Group | Select-Object -First 1 }}}
}
function Edit-FalconIoaExclusion {
<#
.SYNOPSIS
Modify an Indicator of Attack exclusion
.DESCRIPTION
Requires 'IOA Exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER ClRegex
Command line RegEx
.PARAMETER IfnRegex
Image Filename RegEx
.PARAMETER GroupId
Host group identifier or 'all' to apply to all hosts
.PARAMETER Description
Exclusion description
.PARAMETER Comment
Audit log comment
.PARAMETER PatternId
Indicator of Attack pattern identifier
.PARAMETER PatternName
Indicator of Attack pattern name
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconIoaExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [Alias('cl_regex')]
    [string]$ClRegex,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('ifn_regex')]
    [string]$IfnRegex,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('groups','GroupIds')]
    [object[]]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [string]$Comment,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('pattern_id')]
    [string]$PatternId,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('pattern_name')]
    [string]$PatternName,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^([a-fA-F0-9]{32}|all)$')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSCmdlet.ShouldProcess('Edit-FalconIoaExclusion','Test-GroupId')) {
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
function Get-FalconIoaExclusion {
<#
.SYNOPSIS
Search for Indicator of Attack exclusions
.DESCRIPTION
Requires 'IOA Exclusions: Read'.
.PARAMETER Id
Exclusion identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IfnRegex
Filter by Image Filename RegEx pattern
.PARAMETER ClRegex
Filter by Command Line RegEx pattern
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIoaExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/ioa-exclusions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=2)]
    [ValidateSet('applied_globally.asc','applied_globally.desc','created_by.asc','created_by.desc',
      'created_on.asc','created_on.desc','last_modified.asc','last_modified.desc','modified_by.asc',
      'modified_by.desc','name.asc','name.desc','pattern_id.asc','pattern_id.desc','pattern_name.asc',
      'pattern_name.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=4)]
    [Alias('ifn_regex')]
    [string]$IfnRegex,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get',Position=5)]
    [Alias('cl_regex')]
    [string]$ClRegex,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/ioa-exclusions/v1:get')]
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
function New-FalconIoaExclusion {
<#
.SYNOPSIS
Create an Indicator of Attack exclusion
.DESCRIPTION
'ConvertTo-FalconIoaExclusion' can be used to generate the required Indicator of Attack exclusion properties
using an existing detection.

Requires 'IOA Exclusions: Write'.
.PARAMETER Name
Exclusion name
.PARAMETER PatternId
Indicator of Attack pattern identifier
.PARAMETER PatternName
Indicator of Attack pattern name
.PARAMETER ClRegex
Command line RegEx
.PARAMETER IfnRegex
Image Filename RegEx
.PARAMETER GroupId
Host group identifier, or leave undefined to apply to all hosts
.PARAMETER Description
Exclusion description
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconIoaExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^\d+$')]
    [Alias('pattern_id')]
    [string]$PatternId,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('pattern_name')]
    [string]$PatternName,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('cl_regex')]
    [string]$ClRegex,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=5)]
    [Alias('ifn_regex')]
    [string]$IfnRegex,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('groups','GroupIds')]
    [object[]]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
      Position=8)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:post',ValueFromPipelineByPropertyName,
      Position=9)]
    [string]$Comment
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    # Filter to 'id' if supplied with 'detailed' objects
    if ($PSBoundParameters.GroupId.id) { [string[]]$PSBoundParameters.GroupId = $PSBoundParameters.GroupId.id }
    if ($PSBoundParameters.GroupId -eq 'all') {
      # Remove 'all' from 'GroupId', and remove 'GroupId' if 'all' was the only value
      $PSBoundParameters.GroupId = @($PSBoundParameters.GroupId).Where({$_ -ne 'all'})
      if ([string]::IsNullOrEmpty($PSBoundParameters.GroupId)) { [void]$PSBoundParameters.Remove('GroupId') }
    }
    if ($PSBoundParameters.GroupId) {
      @($PSBoundParameters.GroupId).foreach{
        if ($_ -notmatch '^[a-fA-F0-9]{32}$') { throw "'$_' is not a valid Host Group identifier." }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconIoaExclusion {
<#
.SYNOPSIS
Remove Indicator of Attack exclusions
.DESCRIPTION
Requires 'IOA Exclusions: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconIoaExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/ioa-exclusions/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:delete',Position=1)]
    [string]$Comment,
    [Parameter(ParameterSetName='/policy/entities/ioa-exclusions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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