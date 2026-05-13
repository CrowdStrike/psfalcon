function Edit-FalconCloudGcpAccount {
<#
.SYNOPSIS
Modify a Falcon Cloud Security GCP account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER ParentId
GCP parent identifier
.PARAMETER Environment
GCP environment
.PARAMETER ServiceAccount
GCP service account
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCloudGcpAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:patch',Position=1)]
    [Alias('parent_id')]
    [string]$ParentId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:patch',Position=2)]
    [string]$Environment,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:patch',Position=3)]
    [Alias('service_account')]
    [object]$ServiceAccount
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ resources = @('environment','parent_id','service_account') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconCloudGcpServiceAccount {
<#
.SYNOPSIS
Modify a Falcon Cloud Security GCP service account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER ServiceAccountId
Service account identifier
.PARAMETER ServiceAccountCondition
Service account conditions
.PARAMETER ProjectId
Project identifier
.PARAMETER ClientId
Client identifier
.PARAMETER ClientEmail
Client email
.PARAMETER PrivateKeyId
Private key identifier
.PARAMETER PrivateKey
Private key
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCloudGcpServiceAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=1)]
    [Alias('service_account_id')]
    [int32]$ServiceAccountId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=2)]
    [Alias('service_account_conditions')]
    [hashtable[]]$ServiceAccountCondition,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=3)]
    [Alias('project_id')]
    [string]$ProjectId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=4)]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=5)]
    [Alias('client_email')]
    [string]$ClientEmail,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=6)]
    [Alias('private_key_id')]
    [string]$PrivateKeyId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:patch',Mandatory,Position=7)]
    [Alias('private_key')]
    [string]$PrivateKey
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          resources = @('client_email','client_id','private_key','private_key_id','project_id',
            'service_account_conditions','service_account_id')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCloudGcpAccount {
<#
.SYNOPSIS
Search for Falcon Cloud Security GCP accounts
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Id
GCP resource identifier
.PARAMETER ParentType
GCP hierarchy parent type
.PARAMETER ScanType
Scan type
.PARAMETER Status
Account status
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudGcpAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=2)]
    [ValidateSet('Folder','Organization','Project',IgnoreCase=$false)]
    [Alias('parent_type')]
    [string]$ParentType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=3)]
    [ValidateSet('dry','full',IgnoreCase=$false)]
    [Alias('scan-type')]
    [string]$ScanType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=4)]
    [ValidateSet('operational','provisioned',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=5)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get',Position=6)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','limit','offset','parent_type','scan-type','sort','status') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) } } else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconCloudGcpServiceAccount {
<#
.SYNOPSIS
Retrieve service account and email information for a Falcon Cloud Security GCP service account
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Id
GCP service account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudGcpServiceAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=1)]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('id') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Invoke-FalconCloudGcpHealthCheck {
<#
.SYNOPSIS
Perform a synchronous health check for a Falcon Cloud Security GCP parent account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER ParentId
GCP parent account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconCloudGcpHealthCheck
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/account/validate/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/validate/v1:post',Position=1)]
    [Alias('parent_id')]
    [string]$ParentId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ resources = @('parent_id') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconCloudGcpAccount {
<#
.SYNOPSIS
Create a Falcon Cloud Security GCP account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER ParentId
Parent identifier
.PARAMETER ParentType
Parent type
.PARAMETER ServiceAccountId
Service account identifier
.PARAMETER ServiceAccountCondition
Service account conditions
.PARAMETER ProjectId
Project identifier
.PARAMETER ClientId
Client identifier
.PARAMETER ClientEmail
Client email
.PARAMETER PrivateKeyId
Private key identifier
.PARAMETER PrivateKey
Private key
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCloudGcpAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=1)]
    [Alias('parent_id')]
    [string]$ParentId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=2)]
    [Alias('parent_type')]
    [string]$ParentType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=3)]
    [Alias('service_account_id')]
    [int32]$ServiceAccountId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=4)]
    [Alias('service_account_conditions')]
    [hashtable[]]$ServiceAccountCondition,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=5)]
    [Alias('project_id')]
    [string]$ProjectId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=6)]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=7)]
    [Alias('client_email')]
    [string]$ClientEmail,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=8)]
    [Alias('private_key_id')]
    [string]$PrivateKeyId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v2:post',Position=9)]
    [Alias('private_key')]
    [string]$PrivateKey
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          resources = @('client_email','client_id','parent_id','parent_type','private_key','private_key_id',
            'project_id','service_account_conditions','service_account_id')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconCloudGcpScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Cloud Security access using Google Cloud Shell
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Id
GCP resource identifier
.PARAMETER ParentType
GCP hierarchy parent type
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconCloudGcpScript
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/user-scripts-download/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/user-scripts-download/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/user-scripts-download/v1:get',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('Folder','Organization','Project',IgnoreCase=$false)]
    [Alias('parent_type')]
    [string]$ParentType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/user-scripts-download/v1:get',Mandatory,
      Position=3)]
    [string]$Path,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/user-scripts-download/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = @{
        Outfile = 'path'
        Query = @('ids','parent_type')
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
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
function Remove-FalconCloudGcpAccount {
<#
.SYNOPSIS
Remove Falcon Cloud Security GCP accounts
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER Id
GCP resource identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCloudGcpAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/account/v1:delete',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=1)]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
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
function Test-FalconCloudGcpServiceAccount {
<#
.SYNOPSIS
Validate the credentials for a Falcon Cloud Security GCP service account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER ServiceAccountId
Service account identifier
.PARAMETER ServiceAccountCondition
Service account conditions
.PARAMETER ProjectId
Project identifier
.PARAMETER ClientId
Client identifier
.PARAMETER ClientEmail
Client email
.PARAMETER PrivateKeyId
Private key identifier
.PARAMETER PrivateKey
Private key
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconCloudGcpServiceAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=1)]
    [Alias('service_account_id')]
    [int32]$ServiceAccountId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=2)]
    [Alias('service_account_conditions')]
    [hashtable[]]$ServiceAccountCondition,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=3)]
    [Alias('project_id')]
    [string]$ProjectId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=4)]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=5)]
    [Alias('client_email')]
    [string]$ClientEmail,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=6)]
    [Alias('private_key_id')]
    [string]$PrivateKeyId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1:post',Mandatory,
      Position=7)]
    [Alias('private_key')]
    [string]$PrivateKey
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          resources = @('client_email','client_id','private_key','private_key_id','project_id',
            'service_account_conditions','service_account_id')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}