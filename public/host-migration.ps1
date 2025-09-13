function Get-FalconMigration {
<#
.SYNOPSIS
Search for Falcon host migration jobs
.DESCRIPTION
Requires 'Host Migration: Read'.
.PARAMETER Id
Falcon host migration job identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/queries/migrations/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids','migration_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get',Position=2)]
    [ValidateSet('created_by|asc','created_by|desc','created_time|asc','created_time|desc','id|asc','id|desc',
      'migration_id|asc','migration_id|desc','migration_status|asc','migration_status|desc','name|asc',
      'name|desc','status|asc','status|desc','target_cid|asc','target_cid|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get',Position=3)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/host-migration/queries/migrations/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconMigrationCid {
<#
.SYNOPSIS
Search for available Falcon host migration destination CIDs
.DESCRIPTION
Requires 'Host Migration: Read'.
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMigrationCid
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migration-destinations/GET/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migration-destinations/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('device_ids','device_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      for ($i = 0; $i -lt $List.Count; $i += 500) {
        $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Get-FalconMigrationHost {
<#
.SYNOPSIS
Search for hosts in a Falcon host migration job
.DESCRIPTION
Requires 'Host Migration: Read'.
.PARAMETER Id
Host identifier
.PARAMETER JobId
Host migration job identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMigrationHost
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/queries/host-migrations/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/host-migrations/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get',Mandatory,Position=1)]
    [Alias('migration_id')]
    [string]$JobId,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get',Position=3)]
    [ValidateSet('id|asc','id|desc','created_time|asc','created_time|desc','groups|asc','groups|desc',
      'static_host_groups|asc','static_host_groups|desc','target_cid|asc','target_cid|desc','source_cid|asc',
      'source_cid|desc','migration_id|asc','migration_id|desc','hostgroups|asc','hostgroups|desc','hostname|asc',
      'hostname|desc','status|asc','status|desc','host_migration_id|asc','host_migration_id|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get',Position=4)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/host-migration/queries/host-migrations/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } else {
      $PSBoundParameters['id'] = $PSBoundParameters.JobId
      [void]$PSBoundParameters.Remove('JobId')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      $PSBoundParameters['ids'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Invoke-FalconMigrationAction {
<#
.SYNOPSIS
Perform actions on host migration jobs
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Id
Host migration job identifier
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier, when adding or removing groups from migration jobs that have not started
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconMigrationAction
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/host-migrations-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/host-migrations-actions/v1:post',Mandatory,Position=1)]
    [Alias('migration_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/host-migration/entities/host-migrations-actions/v1:post',Mandatory,Position=2)]
    [ValidateSet('add_host_groups','remove_host_groups','remove_hosts',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/host-migration/entities/host-migrations-actions/v1:post',Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId,
    [Parameter(ParameterSetName='/host-migration/entities/host-migrations-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [Alias('ids','device_ids','device_id')]
    [string[]]$HostId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('action_name','id'); Body = @{ root = @('ids','action_parameters') }}
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($HostId) { @($HostId).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $IdValue = $PSBoundParameters.GroupId
      @('GroupId','HostId').foreach{ [void]$PSBoundParameters.Remove($_) }
      if ($PSBoundParameters.Name -eq 'remove_hosts') {
        for ($i = 0; $i -lt $List.Count; $i += 500) {
          $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
          Invoke-Falcon @Param -UserInput $PSBoundParameters
        }
      } else {
        if (!$IdValue) { throw ('Must include "GroupId" with action "{0}".' -f $PSBoundParameters.Name) }
        for ($i = 0; $i -lt $List.Count; $i += 500) {
          $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
          $PSBoundParameters['action_parameters'] = @(@{ name = 'host_group'; value = $IdValue })
          Invoke-Falcon @Param -UserInput $PSBoundParameters
        }
      }
    }
  }
}
function New-FalconMigration {
<#
.SYNOPSIS
Create a Falcon host migration job
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Name
Migration job name
.PARAMETER Cid
Target customer identifier
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migrations/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/host-migration/entities/migrations/v1:post',Position=2)]
    [Alias('target_cid')]
    [string]$Cid,
    [Parameter(ParameterSetName='/host-migration/entities/migrations/v1:post',Position=3)]
    [Alias('device_ids','device_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      for ($i = 0; $i -lt $List.Count; $i += 500) {
        $PSBoundParameters['device_ids'] = @($List[$i..($i + 499)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Start-FalconMigration {
<#
.SYNOPSIS
Start Falcon host migration jobs
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Id
Host migration job identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Start-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migrations-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations-actions/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=1)]
    [Alias('ids','migration_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('ids') }; Query = @('action_name') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      $PSBoundParameters['action_name'] = 'start_migration'
      for ($i = 0; $i -lt $List.Count; $i += 500) {
        $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Stop-FalconMigration {
<#
.SYNOPSIS
Cancel Falcon host migration jobs that haven't started or stop started jobs
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Id
Host migration job identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Stop-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migrations-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations-actions/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=1)]
    [Alias('ids','migration_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('ids') }; Query = @('action_name') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      $PSBoundParameters['action_name'] = 'stop_migration'
      for ($i = 0; $i -lt $List.Count; $i += 500) {
        $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconMigration {
<#
.SYNOPSIS
Remove Falcon host migration jobs
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Id
Host migration job identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migrations-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations-actions/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=1)]
    [Alias('ids','migration_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('ids') }; Query = @('action_name') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('Id')
      $PSBoundParameters['action_name'] = 'delete_migration'
      for ($i = 0; $i -lt $List.Count; $i += 500) {
        $PSBoundParameters['ids'] = @($List[$i..($i + 499)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Rename-FalconMigration {
<#
.SYNOPSIS
Rename a Falcon host migration job
.DESCRIPTION
Requires 'Host Migration: Write'.
.PARAMETER Name
Host migration job name
.PARAMETER Id
Host migration job identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Rename-FalconMigration
#>
  [CmdletBinding(DefaultParameterSetName='/host-migration/entities/migrations-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/host-migration/entities/migrations-actions/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/host-migration/entities/migrations-actions/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory,Position=2)]
    [Alias('ids','migration_id')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('action_name'); Body = @{ root = @('ids','action_parameters') }}
    }
  }
  process {
    $PSBoundParameters['action_name'] = 'rename_migration'
    $PSBoundParameters['action_parameters'] = @(@{ name = 'migration_name'; value = $PSBoundParameters.Name })
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}