function Edit-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Modify a Falcon Horizon AWS account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER AccountId
AWS account identifier
.PARAMETER CloudtrailRegion
AWS region where the account resides
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconHorizonAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^\d{12}$')]
    [Alias('account_id','id')]
    [string]$AccountId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('cloudtrail_region')]
    [string]$CloudtrailRegion
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Search for Falcon Horizon AWS accounts
.DESCRIPTION
A properly provisioned AWS account will display the status 'Event_DiscoverAccountStatusOperational'.

Requires 'CSPM registration: Read'.
.PARAMETER Id
AWS account identifier
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
AWS account status
.PARAMETER GroupBy
Field to group by
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^\d{12}$')]
    [Alias('Ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=1)]
    [ValidatePattern('^o-[0-9a-z]{10,32}$')]
    [Alias('organization-ids','OrganizationIds')]
    [string[]]$OrganizationId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=2)]
    [ValidateSet('full','dry',IgnoreCase=$false)]
    [Alias('scan-type')]
    [string]$ScanType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=3)]
    [ValidateSet('provisioned','operational',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=4)]
    [ValidateSet('organization',IgnoreCase=$false)]
    [Alias('group_by')]
    [string]$GroupBy,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=5)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconHorizonAwsLink {
<#
.SYNOPSIS
Retrieve a URL to grant Falcon Horizon access in AWS
.DESCRIPTION
Once logging in to the provided link using your AWS administrator credentials, use the 'Create Stack' button to
grant access.

Requires 'CSPM registration: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonAwsLink
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/console-setup-urls/v1:get',
    SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}
function New-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Provision a Falcon Horizon AWS account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER CloudtrailRegion
AWS region where the account resides
.PARAMETER AccountId
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconHorizonAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^\d{12}$')]
    [Alias('account_id')]
    [string]$AccountId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^\d{12}$')]
    [Alias('organization_id')]
    [string]$OrganizationId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('cloudtrail_region')]
    [string]$CloudtrailRegion
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconHorizonAwsScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Horizon access using the AWS CLI
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconHorizonAwsScript
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get',Mandatory,
      Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = @{ Outfile = 'path' }
    }
  }
  process {
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'sh'
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Remove Falcon Horizon AWS accounts
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER Id
AWS account identifier
.PARAMETER OrganizationId
AWS organization identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconHorizonAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^\d{12}$')]
    [Alias('Ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='OrganizationIds',Mandatory)]
    [ValidatePattern('^o-[0-9a-z]{10,32}$')]
    [Alias('organization-ids','OrganizationIds')]
    [string[]]$OrganizationId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/cloud-connect-cspm-aws/entities/account/v1:delete'
      Format = @{ Query = @('ids','organization-ids') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}