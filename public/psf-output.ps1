function Export-FalconReport {
<#
.SYNOPSIS
Format a response object and output to console or CSV
.DESCRIPTION
Each property within a response object is 'flattened' to a single field containing a CSV-compatible value--with
each column having an appended 'prefix'--and then exported to the console or designated file path.

For instance, if the object contains a property called 'device_policies', and that contains other objects called
'prevention' and 'sensor_update', the result will contain properties labelled 'device_policies.prevention' and
'device_policies.sensor_update' with additional '.<field_name>' values for any sub-properties of those objects.

When the result contains an array with similarly named properties, it will attempt to add each sub-property with
an additional 'id' prefix based on the value of an existing 'id' or 'policy_id' property. For example,
@{ hosts = @( @{ device_id = 123; hostname = 'abc' }, @{ device_id = 456; hostname = 'def' })} will be displayed
under the columns 'hosts.123.hostname' and 'hosts.456.hostname'. The 'device_id' property is excluded as it
becomes a column.

There is potential for data loss due to object manipulation. Use 'ConvertTo-Json' to ensure all object properties
are retained when integrity is a concern.
.PARAMETER Path
Destination path
.PARAMETER Object
Response object to format
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Export-FalconReport
#>
  [CmdletBinding()]
  param(
    [Parameter(Position=1)]
    [ValidatePattern('\.csv$')]
    [string]$Path,
    [Parameter(Mandatory,ValueFromPipeline,Position=2)]
    [object[]]$Object
  )
  begin {
    function Get-Array ($Array,$Output,$Name) {
      foreach ($Item in $Array) {
        if ($Item.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
          # Add sub-objects to output
          $IdField = $Item.PSObject.Properties.Name -match '^(id|(device|policy)_id)$'
          if ($IdField) {
            $ObjectParam = @{
              Object = $Item | Select-Object -ExcludeProperty $IdField
              Output = $Output
              Prefix = $Name,$Item.$IdField -join '.'
            }
            Get-PSObject @ObjectParam
          } else {
            $ObjectParam = @{ Object = $Item; Output = $Output; Prefix = $Name }
            Get-PSObject @ObjectParam
          }
        } else {
          # Add property to output as 'name'
          $SetParam = @{ Object = $Output; Name = $Name; Value = $Array -join ',' }
          Set-Property @SetParam
        }
      }
    }
    function Get-PSObject ($Object,$Output,$Prefix) {
      foreach ($Item in ($Object.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })) {
        if ($Item.Value.PSObject.TypeNames -contains 'System.Object[]') {
          # Add array members to output with 'prefix.name'
          $ArrayParam = @{
            Array = $Item.Value
            Output = $Output
            Name = if ($Prefix) { $Prefix,$Item.Name -join '.' } else { $Item.Name }
          }
          Get-Array @ArrayParam
        } elseif ($Item.Value.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
          # Add sub-objects to output with 'prefix.name'
          $ObjectParam = @{
            Object = $Item.Value
            Output = $Output
            Prefix = if ($Prefix) { $Prefix,$Item.Name -join '.' } else { $Item.Name }
          }
          Get-PSObject @ObjectParam
        } else {
          # Add property to output with 'prefix.name'
          $SetParam = @{
            Object = $Output
            Name = if ($Prefix) { $Prefix,$Item.Name -join '.' } else { $Item.Name }
            Value = $Item.Value
          }
          Set-Property @SetParam
        }
      }
    }
    if ($Path) { $Path = $Script:Falcon.Api.Path($Path) }
    [System.Collections.Generic.List[object]]$List = @()
  }
  process { if ($Object) { @($Object).foreach{ $List.Add($_) }}}
  end {
    $OutPath = Test-OutFile $Path
    if ($OutPath.Category -eq 'WriteError' -and !$Force) {
      Write-Error @OutPath
    } elseif ($List) {
      [object[]]$Output = @($List).foreach{
        $i = [PSCustomObject]@{}
        if ($_.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
          # Add sorted properties to output
          Get-PSObject $_ $i
        } else {
          # Add strings to output as 'id'
          Set-Property $i id $_
        }
        $i
      }
      if ($Output) {
        # Select all available property names
        [string[]]$Select = @($Output).foreach{ $_.PSObject.Properties.Name } | Select-Object -Unique
        if ($Path) {
          # Export to CSV, forcing all properties
          $Output | Select-Object $Select | Export-Csv $Path -NoTypeInformation -Append
        } else {
          # Export to console, forcing all properties
          $Output | Select-Object $Select
        }
      }
    }
    if ($Path -and (Test-Path $Path)) {
      Get-ChildItem $Path | Select-Object FullName,Length,LastWriteTime
    }
  }
}
function Send-FalconWebhook {
<#
.SYNOPSIS
Send a PSFalcon object to a supported Webhook
.DESCRIPTION
Sends an object to a Webhook, converting the object to an acceptable format when required
.PARAMETER Type
Webhook type
.PARAMETER Path
Webhook URL
.PARAMETER Label
Message label
.PARAMETER Object
Response object to format
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconWebhook
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,Position=1)]
    [ValidateSet('Slack')]
    [string]$Type,
    [Parameter(Mandatory,Position=2)]
    [System.Uri]$Path,
    [Parameter(Position=3)]
    [string]$Label,
    [Parameter(Mandatory,ValueFromPipeline,Position=4)]
    [object]$Object
  )
  begin {
    $Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
      # Remove default Falcon authorization token
      $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization
      [void]$Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
    }
  }
  process {
    [object[]]$Content = switch ($PSBoundParameters.Type) {
      'Slack' {
        # Create 'attachment' for each object in submission
        @($Object | Export-FalconReport).foreach{
          [object[]]$Fields = @($_.PSObject.Properties).foreach{
            ,@{
              title = $_.Name
              value = if ($_.Value -is [boolean]) {
                # Convert [boolean] to [string]
                if ($_.Value -eq $true) { 'true' } else { 'false' }
              } else {
                # Add [string] value when $null
                if ($null -eq $_.Value) { 'null' } else { $_.Value }
              }
              short = $false
            }
          }
          ,@{
            username = 'PSFalcon',$Script:Falcon.ClientId -join ': '
            icon_url = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/icon.png'
            text = $PSBoundParameters.Label
            attachments = @(
              @{
                fallback = 'Send-FalconWebhook'
                fields = $Fields
              }
            )
          }
        }
      }
    }
    foreach ($Item in $Content) {
      try {
        $Param = @{
          Path = $PSBoundParameters.Path
          Method = 'post'
          Headers = @{ ContentType = 'application/json' }
          Body = ConvertTo-Json $Item -Depth 32
        }
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result $Request
      } catch {
        throw $_
      }
    }
  }
  end {
    if ($Token -and !$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
      # Restore default Falcon authorization token
      $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization',$Token)
    }
  }
}
function Show-FalconMap {
<#
.SYNOPSIS
Display indicators on the Falcon Intelligence Indicator Map
.DESCRIPTION
Your default web browser will be used to view the Indicator Map.

Show-FalconMap will accept domains, SHA256 hashes, IP addresses and URLs. Invalid indicator values are ignored.
.PARAMETER Indicator
Indicator to display on the Indicator map
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconMap
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,ValueFromPipeline,Position=1)]
    [Alias('Indicators')]
    [string[]]$Indicator
  )
  begin {
    [string]$FalconUI = "$($Script:Falcon.Hostname -replace 'api','falcon')"
    $List = [System.Collections.Generic.List[string]]@()
  }
  process {
    if ($Indicator) {
      @($Indicator).foreach{
        if ($_ -match '^(domain|hash|ip_address|url)_') {
          # Split indicators from 'Get-FalconIndicator'
          [string]$String = switch -Regex ($_) {
            '^domain_' { $_ -replace '_',':' }
            '^hash_sha256' { @('hash',($_ -split '_')[-1]) -join ':' }
            '^ip_address_' { $_ -replace '_address_',':' }
            '^url_' {
              $Value = ([System.Uri]($_ -replace 'url_',$null)).Host
              $Type = Test-RegexValue $Value
              if ($Type -match 'ipv(4|6)') { $Type = 'ip' }
              if ($Type -and $Value) { @($Type,$Value) -join ':' }
            }
          }
          if ($String) { $List.Add($String) }
        } else {
          $Type = Test-RegexValue $_
          if ($Type -match 'ipv(4|6)') { $Type = 'ip' }
          $Value = if ($Type -match '^(domain|md5|sha256)$') { $_.ToLower() } else { $_ }
          if ($Type -and $Value) { $List.Add("$($Type):'$Value'") }
        }
      }
    }
  }
  end {
    if ($List) {
      [string[]]$IocInput = @($List) -join ','
      if (!$IocInput) { throw "No valid indicators found." }
      [string]$Target = "$($FalconUI)/intelligence/graph?indicators=$($IocInput -join ',')"
      if ($PSCmdlet.ShouldProcess($Target)) { Start-Process $Target }
    }
  }
}
function Show-FalconModule {
<#
.SYNOPSIS
Display information about your PSFalcon module
.DESCRIPTION
Outputs an object containing module, user and system version information that is helpful for diagnosing problems
with the PSFalcon module.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconModule
#>
  [CmdletBinding()]
  param()
  process {
    $ManifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSFalcon.psd1'
    if (Test-Path $ManifestPath) {
      $ModuleData = Import-PowerShellDataFile -Path $ManifestPath
      [PSCustomObject]@{
        PSVersion = "$($PSVersionTable.PSEdition) [$($PSVersionTable.PSVersion)]"
        ModuleVersion = "v$($ModuleData.ModuleVersion) {$($ModuleData.GUID)}"
        ModulePath = Split-Path $ManifestPath -Parent
        UserModulePath = $env:PSModulePath
        UserHome = $HOME
        UserAgent = $Script:Falcon.Api.UserAgent
      }
    } else {
      throw "Unable to locate '$ManifestPath'."
    }
  }
}