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
A hashtable containing the following keys with the corresponding CSV column or rule property name as the value. A
default map will be used if one is not provided.

Mandatory: action, description, direction, enabled, local_address, name, protocol, remote_address
Optional: fqdn, fqdn_enabled, image_name, local_port, network_location, platform_ids, remote_port, service_name
.PARAMETER Path
Path to a CSV file containing rules to convert
.PARAMETER Object
A rule object to convert
.LINK
https://github.com/crowdstrike/psfalcon/wiki/ConvertTo-FalconFirewallRule
#>
  [CmdletBinding()]
  [OutputType([hashtable[]])]
  param(
    [Parameter(ParameterSetName='Pipeline',Position=1)]
    [Parameter(ParameterSetName='CSV',Position=1)]
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

    function Get-RuleAction ([object]$Obj) {
      # Convert 'BLOCK' to 'DENY', otherwise use capitalized 'action'
      if ($Obj.($UserMap.action) -eq 'BLOCK') { 'DENY' } else { $Obj.($UserMap.action).ToUpper() }
    }
    function Get-RuleDirection ([object]$Obj) {
      try { [regex]::Match($Obj.($UserMap.direction),'^(in|out|both)',1).Value.ToUpper() } catch {}
    }
    function Get-RuleFamily ([object]$Obj,[string]$Protocol,[string[]]$TypeList) {
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
    function Get-RuleProtocol ([object]$Obj) {
      if ($Obj.($UserMap.protocol) -match $Regex.Any) {
        # Use asterisk for 'any'
        '*'
      } elseif ($Obj.($UserMap.protocol) -as [int] -is [int]) {
        # Use existing integer value
        $Obj.($UserMap.protocol)
      } else {
        switch ($Obj.($UserMap.protocol)) {
          # Convert expected protocol names to their numerical value
          'icmpv4' { '1' }
          'tcp' { '6' }
          'udp' { '17' }
          'icmpv6' { '58' }
        }
      }
    }
    function New-RuleAddress ([string]$String,[string]$ObjName) {
      foreach ($Address in ($String -split $Regex.Join)) {
        # Remove excess spaces
        [string]$Address = $Address.Trim()
        if ($Address -match $Regex.Any) {
          # Output 'any' address and netmask
          @{ address = '*'; netmask = 0 }
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
            throw "Rule '$ObjName' contains an address that does not match IPv4 or IPv6 pattern. ['$($Address)']"
          }
          if ($Address -and $Integer) {
            # Output object with address and netmask
            @{ address = $Address; netmask = $Integer }
          }
        }
      }
    }
    function New-RuleField ([object]$Obj) {
      # Create default 'fields' array containing 'network_location'
      @{
        name = 'network_location'
        type = 'set'
        values = if ($Obj.($UserMap.network_location) -and $Obj.($UserMap.network_location).Trim() -notmatch
        $Regex.Any) {
          # Add 'network_location' values
          ,@(($Obj.($UserMap.network_location) -split $Regex.Join).Trim())
        } else {
          ,@('ANY')
        }
      }
    }
    function New-RulePort ([string]$String) {
      if ($String -notmatch $Regex.Any) {
        # Create 'port' objects
        @($String -split $Regex.Join).Trim().foreach{
          if ($_ -match '-') {
            # Split ranges into 'start' and 'end'
            [int[]]$Range = ($_ -split '-',2).Trim()
            @{ start = $Range[0]; end = $Range[1] }
          } else {
            # Create separate objects for each value when multiple are provided
            @{ start = [int]$_; end = 0 }
          }
        }
      }
    }
    function Convert-RuleObject ([object]$Obj) {
      # Set RegEx pattern to split port/address strings and create object string for error messaging
      try {
        [string]$Protocol = Get-RuleProtocol $Obj
        if (!$Protocol) {
          throw "Rule '$($Obj.($UserMap.name))' contains unexpected protocol '$($Obj.($UserMap.protocol))'."
        }
        [string[]]$TypeList = foreach ($Type in ('local_address','remote_address')) {
          @($Obj.($UserMap.$Type) -split $Regex.Join).foreach{
            if ($_.Trim() -match $Regex.Any) {
              'ANY'
            } else {
              # Error when 'local_address' or 'remote_address' does not match ipv4/ipv6
              [string]$Trim = ($_.Trim() -replace '/\d+$',$null)
              if (!$Trim) { throw "Rule '$($Obj.($UserMap.name))' missing value for required property '$Type'." }
              [string]$Test = Test-RegexValue $Trim
              if ($Test -match '^ipv(4|6)$') {
                [string]($Test -replace 'v',$null).ToUpper()
              } else {
                throw "Rule '$($Obj.($UserMap.name))' contains unexpected $Type '$Trim'."
              }
            }
          }
        }
        if ($TypeList -contains 'IP4' -and $TypeList -contains 'IP6') {
          # Error when rules contain both ipv4 and ipv6 addresses
          throw "Rule '$($Obj.($UserMap.name))' contains both ipv4 and ipv6 addresses."
        } else {
          foreach ($Name in ('action','address_family','direction')) {
            # Set 'action', 'family' and 'direction'
            $Value = if ($Name -eq 'address_family') {
              Get-RuleFamily $Obj $Protocol $TypeList
            } else {
              & "Get-Rule$Name" $Obj
            }
            if ($Name -eq 'address_family' -and $Value -cnotmatch '^IP[4|6]$') {
              # Error when unexpected value is provided
              throw "Unable to determine $Name for rule '$($Obj.($UserMap.name))'."
            } elseif (($Name -eq 'action' -and $Value -cnotmatch '^(ALLOW|DENY)$') -or
            ($Name -eq 'direction' -and $Value -cnotmatch '^(BOTH|IN|OUT)$')) {
              throw "Rule '$($Obj.($UserMap.name))' contains unexpected $Name '$($Obj.($UserMap.$Name))'."
            } else {
              New-Variable -Name $Name -Value $Value
            }
          }
          # Output rule object
          $Output = @{
            action = $action
            address_family = $address_family
            description = $Obj.($UserMap.description)
            direction = $direction
            enabled = if ($Obj.($UserMap.enabled) -match '$?true') { $true } else { $false }
            fields = [System.Collections.Generic.List[hashtable]]@()
            fqdn = if ($Obj.($UserMap.fqdn)) { $Obj.($UserMap.fqdn) } else { '' }
            fqdn_enabled = if ($Obj.($UserMap.fqdn_enabled) -match '$?true') { $true } else { $false }
            local_address = @(New-RuleAddress $Obj.($UserMap.local_address) $Obj.($UserMap.name))
            local_port = @(New-RulePort $Obj.($UserMap.local_port))
            name = $Obj.($UserMap.name)
            platform_ids = @($Obj.($UserMap.platform_ids))
            protocol = $Protocol
            remote_address = @(New-RuleAddress $Obj.($UserMap.remote_address) $Obj.($UserMap.name))
            remote_port = @(New-RulePort $Obj.($UserMap.remote_port))
          }
          # Trim name to 64 characters
          if ($Output.name.Length -gt 64) { $Output.name = ($Output.name).SubString(0,63) }
          $Output.fields.Add((New-RuleField $Obj))
          foreach ($Name in ('image_name','service_name')) {
            # Add 'image_name' and 'service_name' to 'fields', when present
            if ($Obj.($UserMap.$Name) -and $Obj.($UserMap.$Name).Trim() -notmatch $Regex.Any) {
              [string]$Value = if ($Name -eq 'image_name' -and $Obj.($UserMap.$Name) -notmatch '\.\w+$') {
                # Convert directory paths to glob syntax with a single asterisk
                [string]$Glob = $Obj.($UserMap.$Name) -replace '^\w:\\',$null
                if ($Glob -match '\\$') { [string]::Concat($Glob,'*') } else { $Glob,'*' -join '\' }
              } else {
                $Obj.($UserMap.$Name)
              }
              $Output.fields.Add((@{
                name = $Name
                type = if ($_ -eq 'image_name') { 'windows_path' } else { 'string' }
                value = $Value
              }))
            }
          }
          $Output
        }
      } catch {
        throw $_
      }
    }
    # Properties evaluated for rule creation
    [string[]]$Mandatory = 'action','description','direction','enabled','local_address','name','protocol',
      'remote_address'
    [string[]]$Optional = 'fqdn','fqdn_enabled','image_name','local_port','network_location','platform_ids',
      'remote_port','service_name'
    $Regex = @{
      # Regex patterns to use when checking rule content
      Any = '^(any|\*)$'
      Join = '[;,]'
    }
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    # Verify object properties against Map
    if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
      # Capture object for rule creation
      @($Object).foreach{ $List.Add($_) }
    } else {
      # Import CSV and convert rules
      if ($PSBoundParameters.Map) {
        Import-Csv $Path | & $MyInvocation.MyCommand.Name -Map $PSBoundParameters.Map
      } else {
        Import-Csv $Path | & $MyInvocation.MyCommand.Name
      }
    }
  }
  end {
    if ($List) {
      if ($PSBoundParameters.Map) {
        $UserMap = try { $PSBoundParameters.Map.Clone() } catch { throw $_ }
      } else {
        # Generate default 'Map' values
        $UserMap = @{}
        @($Mandatory + $Optional).foreach{ $UserMap[$_] = $_ }
      }
      @($UserMap.Keys).foreach{
        if (!($Mandatory -contains $_ -or $Optional -contains $_)) {
          # Remove keys not defined by 'Mandatory' or 'Optional'
          Write-Log 'ConvertTo-FalconFirewallRule' ('Removed unexpected Map property "{0}"' -f $_)
          [void]$UserMap.Remove($_)
        }
      }
      @($Mandatory).Where({$UserMap.Keys -notcontains $_}).foreach{
        # Error if Map is missing mandatory property
        throw "Map missing mandatory property '$_'!"
      }
      # Convert object using Map-defined properties
      @($List).foreach{ Convert-RuleObject ($_ | Select-Object ([string[]]$UserMap.Values)) }
    }
  }
}
