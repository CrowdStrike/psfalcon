function ConvertTo-FalconFirewallRule {
<#
.SYNOPSIS
Convert firewall rules to be compatible with Falcon Firewall Management
.DESCRIPTION
Ensures that an object (either from the pipeline, or via CSV import) has the required properties to be accepted
as a valid Falcon Firewall Management rule.

Rules that contain both IPv4 and IPv6 addresses will generate errors, along with any rules that are missing the
required properties defined by the 'Map' parameter.

Converted rules used with 'New-FalconFirewallGroup' to create groups containing newly converted rules.
.PARAMETER Map
A hashtable containing the following keys with the corresponding CSV column or rule property as the value

Required: action, description, direction, enabled, local_address, local_port, name, remote_address, remote_port
Optional: image_name, network_location, service_name
.PARAMETER Path
Path to a CSV file containing rules to convert
.PARAMETER Object
An existing rule object to convert
.LINK
https://github.com/crowdstrike/psfalcon/wiki/ConvertTo-FalconFirewallRule
#>
  [CmdletBinding()]
  [OutputType([PSCustomObject[]])]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,Position=1)]
    [Parameter(ParameterSetName='CSV',Mandatory,Position=1)]
    [ValidateScript({
      foreach ($Key in @('action','description','direction','enabled','local_address','local_port','name',
      'remote_address','remote_port')) {
        if ($_.Keys -notcontains $Key) { throw "Missing required '$Key' property." } else { $true }
      }
    })]
    [hashtable]$Map,
    [Parameter(ParameterSetName='CSV',Mandatory,Position=2)]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist or is a directory."
      }
    })]
    [Alias('FullName')]
    [string]$Path,
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [object]$Object
  )
  begin {
    function Get-RuleAction ([object]$Rule,[hashtable]$Map) {
      if ($Rule.($Map.action) -eq 'BLOCK') { 'DENY' } else { $Rule.($Map.action).ToUpper() }
    }
    function Get-RuleDirection ([object]$Rule,[hashtable]$Map) {
      try { [regex]::Match($Rule.($Map.direction),'^(in|out|both)',1).Value.ToUpper() } catch {}
    }
    function Get-RuleFamily ([object]$Rule,[hashtable]$Map,[string]$Protocol,[string[]]$TypeList) {
      if ($Protocol -eq '1') {
        # Force 'IP4' when protocol is 'ICMPv4'
        'IP4'
      } elseif ($Protocol -eq '58') {
        # Force 'IP6' when protocol is 'ICMPv6'
        'IP6'
      } else {
        # Use unique value from 'TypeList' and default to 'IP4' when 'TypeList' is 'ANY'
        [string]$Output = (($TypeList | Select-Object -Unique) -replace 'v',$null -replace 'ANY',$null).ToUpper()
        if ($Output) { ($Output).Trim() } else { 'IP4' }
      }
    }
    function Get-RuleProtocol ([object]$Rule,[hashtable]$Map) {
      if ($Rule.($Map.protocol) -match '^(any|\*)$') {
        # Use asterisk for 'any'
        '*'
      } elseif ($Rule.($Map.protocol) -as [int] -is [int]) {
        # Use existing integer value
        $Rule.($Map.protocol)
      } else {
        switch ($Rule.($Map.protocol)) {
          # Convert expected protocol names to their numerical value
          'icmpv4' { '1' }
          'tcp' { '6' }
          'udp' { '17' }
          'icmpv6' { '58' }
        }
      }
    }
    function New-RuleAddress ([string]$String,[hashtable]$Map,[string]$Join,[string]$RuleName) {
      foreach ($Address in ($String -split $Join)) {
        # Remove excess spaces
        [string]$Address = $Address.Trim()
        if ($Address -match '^(any|\*)$') {
          # Output 'any' address and netmask
          [PSCustomObject]@{ address = '*'; netmask = 0 }
        } else {
          # Check whether address matches ipv4 or ipv6
          [string]$Type = Test-RegexValue ($Address -replace '/\d+$',$null)
          [int]$Integer = if ($Address -match '/') {
            # Collect netmask from CIDR notation
            ($Address -split '/',2)[-1]
            $Address = $Address -replace '/\d+$'
          } elseif ($Type -eq 'ipv6') {
            # Use default for ipv6 address
            128
          } elseif ($Type -eq 'ipv4') {
            # Use default for ipv4 address
            32 
          } else {
            throw "Rule '$RuleName' contains an address that does not match IPv4 or IPv6 pattern. ['$($Address)']"
          }
          # Output object with address and netmask
          if ($Address -and $Integer) { [PSCustomObject]@{ address = $Address; netmask = $Integer }}
        }
      }
    }
    function New-RuleField ([object]$Rule,[hashtable]$Map,[string]$Join) {
      # Create default 'fields' array
      [string[]]$Location = if ($Rule.($Map.network_location) -and ($Rule.($Map.network_location) -notmatch
      '^(any|\*)$')) {
        # Add 'network_location' values
        @($Rule.($Map.network_location) -split $Join).foreach{ $_ }
      } else {
        'ANY'
      }
      [PSCustomObject[]]([PSCustomObject]@{ name = 'network_location'; type = 'set'; values = $Location })
    }
    function New-RulePort ([string]$String,[string]$Join) {
      if ($String -notmatch '^(any|\*)$') {
        # Create 'port' objects
        @($String -split $Join).foreach{
          if ($_ -match '-') {
            # Split ranges into 'start' and 'end'
            [int[]]$Range = $_ -split '-',2
            [PSCustomObject]@{ start = $Range[0]; end = $Range[1] }
          } else {
            # Create separate objects for each value when multiple are provided
            [PSCustomObject]@{ start = [int]$_; end = 0 }
          }
        }
      }
    }
    function Convert-RuleObject ([object]$Rule,[hashtable]$Map) {
      # Set RegEx pattern to split port/address strings and create object string for error messaging
      [string]$Join = '[;,-]'
      try {
        [string]$Protocol = Get-RuleProtocol $Rule $Map
        if (!$Protocol) {
          throw "Rule '$($Rule.($Map.name))' contains unexpected protocol '$($Rule.($Map.protocol))'."
        }
        [string[]]$TypeList = foreach ($Type in ('local_address','remote_address')) {
          @($Rule.($Map.$Type) -split $Join).foreach{
            if ($_.Trim() -match '^(any|\*)$') {
              'ANY'
            } else {
              # Error when 'local_address' or 'remote_address' does not match ipv4/ipv6
              [string]$Trim = ($_.Trim() -replace '/\d+$',$null)
              if (!$Trim) { throw "Rule '$($Rule.($Map.name))' missing value for required property '$Type'." }
              [string]$Test = Test-RegexValue $Trim
              if ($Test -match '^ipv(4|6)$') {
                [string]($Test -replace 'v',$null).ToUpper()
              } else {
                throw "Rule '$($Rule.($Map.name))' contains unexpected $Type '$Trim'."
              }
            }
          }
        }
        if ($TypeList -contains 'IP4' -and $TypeList -contains 'IP6') {
          # Error when rules contain both ipv4 and ipv6 addresses
          throw "Rule '$($Rule.($Map.name))' contains both ipv4 and ipv6 addresses."
        } else {
          foreach ($Name in ('action','address_family','direction')) {
            # Set 'action', 'family' and 'direction'
            $Value = if ($Name -eq 'address_family') {
              Get-RuleFamily $Rule $Map $Protocol $TypeList
            } else {
              & "Get-Rule$Name" $Rule $Map
            }
            if ($Name -eq 'address_family' -and $Value -cnotmatch '^IP[4|6]$') {
              # Error when unexpected value is provided
              throw "Unable to determine $Name for rule '$($Rule.($Map.name))'."
            } elseif (($Name -eq 'action' -and $Value -cnotmatch '^(ALLOW|DENY)$') -or
            ($Name -eq 'direction' -and $Value -cnotmatch '^(BOTH|IN|OUT)$')) {
              throw "Rule '$($Rule.($Map.name))' contains unexpected $Name '$($Rule.($Map.$Name))'."
            } else {
              New-Variable -Name $Name -Value $Value
            }
          }
          @('local_address','remote_address').foreach{
            # Create 'local_address' and 'remote_address' objects
            New-Variable -Name $_ -Value ([PSCustomObject[]](
              New-RuleAddress $Rule.($Map.$_) $Map $Join $Rule.($Map.name)))
          }
          # Construct default 'fields'
          [PSCustomObject[]]$Field = New-RuleField $Rule $Map
          foreach ($Name in ('image_name','service_name')) {
            # Add 'image_name' and 'service_name' to 'fields', when present
            if ($Rule.($Map.$Name) -and $Rule.($Map.$Name) -notmatch '^(any|\*)$') {
              [string]$Value = if ($Name -eq 'image_name' -and $Rule.($Map.$Name) -notmatch '\.\w+$') {
                # Convert directory paths to glob syntax with a single asterisk
                [string]$Glob = $Rule.($Map.$Name) -replace '^\w:\\',$null
                if ($Glob -match '\\$') { [string]::Concat($Glob,'*') } else { $Glob,'*' -join '\' }
              } else {
                $Rule.($Map.$Name)
              }
              $Field += [PSCustomObject]@{
                name = $Name
                type = if ($_ -eq 'image_name') { 'windows_path' } else { 'string' }
                value = $Value
              }
            }
          }
          # Create rule object
          $Output = [PSCustomObject]@{
            action = $action
            address_family = $address_family
            description = $Rule.($Map.description)
            direction = $direction
            enabled = if ($Rule.($Map.enabled) -match '$?true') { $true } else { $false }
            fields = $Field
            name = $Rule.($Map.name)
            protocol = $Protocol
            local_address = $local_address
            remote_address = $remote_address
          }
          @('local_port','remote_port').foreach{
            # Add 'local_port' and 'remote_port'
            New-Variable -Name $_ -Value ([PSCustomObject[]](New-RulePort $Rule.($Map.$_) $Join))
            if ((Get-Variable -Name $_).Value) {
              $Output.PSObject.Properties.Add((New-Object PSNoteProperty($_,(Get-Variable -Name $_).Value)))
            }
          }
          $Output
        }
      } catch {
        throw $_
      }
    }
  }
  process {
    if (!$Path) {
      # Convert pipeline object into formatted rule
      Convert-RuleObject ([PSCustomObject]$Object | Select-Object @($Map.Values)) $Map
    }
  }
  end {
    if ($Path) {
      # Import CSV and convert rules to expected format
      Import-Csv $Path | & $MyInvocation.MyCommand.Name -Map $Map
    }
  }
}