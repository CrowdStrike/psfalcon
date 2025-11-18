function Find-FalconDuplicate {
<#
.SYNOPSIS
Find potential duplicate hosts within your Falcon environment
.DESCRIPTION
If 'InputObject' is not provided all host information will be retrieved. If a host does not contain values for
'cid', 'hostname', 'last_seen', and any specified 'Filter', that host will be excluded from evaluation.

Hosts are grouped by 'cid', 'hostname' and any defined 'Filter' values. Any result other than the one with the
most recent 'last_seen' time is considered a duplicate host and is returned within the output.

The list of potential duplicates can be hidden from the Falcon console if provided to 'Invoke-FalconHostAction'
with the action 'hide_host'.

Requires 'Hosts: Read'.
.PARAMETER InputObject
Object array containing detailed host information
.PARAMETER Filter
One or more additional properties to use to determine duplicates
.PARAMETER Platform
Filter list of hosts by one or more 'platform_name' values
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Find-FalconDuplicate
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(ValueFromPipeline,Position=1)]
    [Alias('Hosts')]
    [object[]]$InputObject,
    [Parameter(Position=2)]
    [ValidateSet('external_ip','local_ip','mac_address','os_version','platform_name','serial_number',
      IgnoreCase=$false)]
    [string[]]$Filter,
    [Parameter(Position=3)]
    [ValidateSet('Linux','Mac','Windows',IgnoreCase=$false)]
    [string[]]$Platform
  )
  begin {
    # Required properties for grouping and output
    [System.Collections.Generic.List[string]]$Criteria = @('cid','hostname')
    [System.Collections.Generic.List[string]]$Selected = @('cid','device_id','first_seen','last_seen','hostname')
    if ($Filter) {
      # Add 'Filter' to required properties for grouping and output
      $Criteria.Add($Filter)
      $Selected.Add($Filter)
    }
    if ($Platform) {
      # Add 'platform_name' to output properties when specified
      $Selected.Add('platform_name')
    }
    # Create FilterScript for required properties for grouping, with 'last_seen' for sorting
    $FilterScript = [scriptblock]::Create((@($Criteria + 'last_seen').foreach{
      '![string]::IsNullOrEmpty($_.{0})' -f $_ } -join ' -and '))
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Add filtered pipeline objects to list with required properties
        if (($Platform -and $Platform -contains $_.platform_name) -or !$Platform) {
          $i = [PSCustomObject]$_ | Where-Object -FilterScript $FilterScript | Select-Object $Selected
          if ($i) {
            $List.Add($i)
          } else {
            Write-Log 'Find-FalconDuplicate' ('Ignored host:',([PSCustomObject]$_ |
              Select-Object $Selected | Format-List | Out-String).Trim() -join "`n")
          }
        }
      }
    }
  }
  end {
    if (!$List) {
      if ($PSCmdlet.ShouldProcess('Find-FalconDuplicate','Get-FalconHost')) {
        $Param = @{
          Field = $Selected
          Detailed = $true
          All = $true
          ErrorAction = 'SilentlyContinue'
        }
        if ($Platform) { $Param['Filter'] = "platform_name:[$((@($Platform).foreach{"'$_'"}) -join ',')]" }
        # Retrieve host details and add filtered hosts to list with required properties
        @(Get-FalconHost @Param).foreach{
          $i = [PSCustomObject]$_ | Where-Object -FilterScript $FilterScript
          if ($i) {
            $List.Add($i)
          } else {
            Write-Log 'Find-FalconDuplicate' ('Ignored host:',([PSCustomObject]$_ |
              Select-Object $Selected | Format-List | Out-String).Trim() -join "`n")
          }
        }
      }
    }
    # Output verbose message when grouping starts
    if ($Platform) {
      Write-Log 'Find-FalconDuplicate' ('Grouping {0} {1} hosts by {2}' -f $List.Count,($Platform -join ' and '),
        ((@($Criteria).foreach{"'$_'"}) -join ','))
    } else {
      Write-Log 'Find-FalconDuplicate' ('Grouping {0} hosts by {1}' -f $List.Count,((@($Criteria).foreach{
      "'$_'"}) -join ','))
    }
    # Group by 'cid' and 'hostname', then output all but the host with the most recent 'last_seen' value
    $Output = @($List | Group-Object $Criteria).Where({$_.Count -gt 1 -and $_.Name}).foreach{
      $_.Group | Sort-Object last_seen | Select-Object -First ($_.Count - 1) | Select-Object $Selected
    }
    if ($Output) {
      Write-Log 'Find-FalconDuplicate' ('Found {0} potential duplicates' -f $Output.Count)
      $Output
    } else {
      $PSCmdlet.WriteWarning('[Find-FalconDuplicate] No duplicates found.')
    }
  }
}
function Find-FalconHostname {
<#
.SYNOPSIS
Find hosts using a list of hostnames
.DESCRIPTION
Perform hostname searches in groups of 100.

Requires 'Hosts: Read'.
.PARAMETER InputObject
One or more hostnames to find
.PARAMETER Path
Path to a plain text file containing hostnames
.PARAMETER Include
Include additional properties
.PARAMETER Partial
Perform a non-exact search
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Find-FalconHostname
#>
  [CmdletBinding(DefaultParameterSetName='Path',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [Alias('Array')]
    [string[]]$InputObject,
    [Parameter(ParameterSetName='Path',Mandatory,Position=1)]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist."
      }
    })]
    [string]$Path,
    [Parameter(ParameterSetName='Path',Position=2)]
    [Parameter(ParameterSetName='Pipeline',Position=2)]
    [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip','mac_address',
      'os_build','os_version','platform_name','product_type','product_type_desc','serial_number',
      'system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='Path')]
    [Parameter(ParameterSetName='Pipeline')]
    [switch]$Partial
  )
  begin {
    [System.Collections.Generic.List[string]]$List = @()
    if ($Path) { [string]$Path = $Script:Falcon.Api.Path($Path) }
    [string[]]$Select = 'device_id','hostname'
    if ($Include) { $Select += $Include }
  }
  process {
    if ($Path) {
      $List.AddRange([string[]]((Get-Content -Path $Path).Normalize()).Where({
        ![string]::IsNullOrWhiteSpace($_)}))
    } elseif ($InputObject) {
      @($InputObject).Where({![string]::IsNullOrWhiteSpace($_)}).foreach{ $List.Add($_) }
    }
  }
  end {
    if ($List) {
      $List = @($List) | Select-Object -Unique
      for ($i=0; $i -lt ($List | Measure-Object).Count; $i+=100) {
        [string[]]$Group = @($List)[$i..($i+99)]
        [string]$Filter = if ($Partial) {
          (@($Group).foreach{ "hostname:'$_'" }) -join ','
        } else {
          (@($Group).foreach{ "hostname:['$_']" }) -join ','
        }
        $Req = Get-FalconHost -Filter $Filter -Field $Select -Detailed
        @($Group).foreach{
          if (($Partial -and $Req.hostname -notlike "$_*") -or (!$Partial -and $Req.hostname -notcontains $_)) {
            $PSCmdlet.WriteWarning("[Find-FalconHostname] No match found for '$_'.")
          }
        }
        if ($Req) { $Req }
      }
    }
  }
}