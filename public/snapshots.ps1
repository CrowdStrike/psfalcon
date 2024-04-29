function New-CommandName {
<#
.SYNOPSIS
Retrieve snapshot jobs identified by the provided IDs
.DESCRIPTION
Requires 'Snapshot: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results

Search snapshot jobs using a query in Falcon Query Language (FQL). Supported filters:  account_id,asset_identifier,cloud_provider,region,status
.PARAMETER Limit
Maximum number of results per request

The upper-bound on the number of records to retrieve.
.PARAMETER Offset
Position to begin retrieving results

The offset from where to begin.
.PARAMETER Sort
Property and direction to sort results

The fields to sort the records on. Supported columns:  [account_id asset_identifier cloud_provider instance_type last_updated_timestamp region status]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/combined/deployments/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=0)]
    [string]$Filter,
    [ValidateScript({ Test-FqlStatement $_ })]
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=0)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=0)]
    [string]$Sort
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Register customer cloud account for snapshot scanning
.DESCRIPTION
Requires 'Snapshot: Write'.
.PARAMETER AccountNumber

.PARAMETER BatchRegions

.PARAMETER IamExternalId

.PARAMETER IamRoleArn

.PARAMETER KmsAlias

.PARAMETER ProcessingAccount

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/accounts/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('account_number')]
    [string]$AccountNumber,
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('batch_regions')]
    [domain.AWSBatchClusterRegion]$BatchRegions,
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('iam_external_id')]
    [string]$IamExternalId,
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('iam_role_arn')]
    [string]$IamRoleArn,
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('kms_alias')]
    [string]$KmsAlias,
    [Parameter(ParameterSetName='/snapshots/entities/accounts/v1:post',Position=0)]
    [Alias('processing_account')]
    [string]$ProcessingAccount
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Retrieve snapshot jobs identified by the provided IDs
.DESCRIPTION
Requires 'Snapshot: Read'.
.PARAMETER Id
XXX identifier

Search snapshot jobs by ids - The maximum amount is 100 IDs
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/deployments/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:get',ValueFromPipelineByPropertyName,ValueFromPipeline)]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-CommandName {
<#
.SYNOPSIS
Launch a snapshot scan for a given cloud asset
.DESCRIPTION
Requires 'Snapshot: Write'.
.PARAMETER AccountId

.PARAMETER AssetIdentifier

.PARAMETER CloudProvider

.PARAMETER Region

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/deployments/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Position=0)]
    [Alias('account_id')]
    [string]$AccountId,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Position=0)]
    [Alias('asset_identifier')]
    [string]$AssetIdentifier,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Position=0)]
    [Alias('cloud_provider')]
    [string]$CloudProvider,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Mandatory,Position=0)]
    [string]$Region
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Gets the registry credentials
.DESCRIPTION
Requires 'Snapshot Scanner Image Download: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/image-registry-credentials/v1:get',SupportsShouldProcess)]
  param()
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}

}
function New-CommandName {
<#
.SYNOPSIS
retrieve the scan report for an instance
.DESCRIPTION
Requires 'Snapshot: Read'.
.PARAMETER Id
XXX identifier

the instance identifiers to fetch the report for
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/scanreports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/scanreports/v1:get',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline)]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
