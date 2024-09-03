#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a custom IOA rule group with 'network_connection' rules using a list of IPv4 addresses within a text file
.DESCRIPTION
IPv4 addresses will be converted into RegEx and condensed into a single rule when 2 or more octets match

Requires 'Custom IOA rules: Write'.
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER MemberCid
Member CID, used when authenticating within a multi-CID environment ('Falcon Flight Control')
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Path
Path to text file containing IPv4 addresses
.PARAMETER Platform
Operating system platform
.PARAMETER GroupName
Rule group name
.PARAMETER Severity
Rule severity
.PARAMETER DispositionId
Disposition identifier [10: Monitor, 20: Detect, 30: Block]
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(Position=3)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$MemberCid,
  [Parameter(Position=4)]
  [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
  [string]$Cloud,
  [Parameter(Mandatory,Position=5)]
  [ValidatePattern('\.txt$')]
  [ValidateScript({
    if (Test-Path -Path $_ -PathType Leaf) {
      $true
    } else {
      throw "Cannot find path '$_' because it does not exist or is a directory."
    }
  })]
  [string]$Path,
  [Parameter(Mandatory,Position=6)]
  [ValidateSet('windows','mac','linux',IgnoreCase=$false)]
  [string]$Platform,
  [Parameter(Mandatory,Position=7)]
  [string]$GroupName,
  [Parameter(Mandatory,Position=8)]
  [ValidateSet('critical','high','medium','low','informational',IgnoreCase=$false)]
  [string]$Severity,
  [Parameter(Mandatory,Position=9)]
  [ValidateSet(10,20,30)]
  [int32]$DispositionId
)
begin {
  function Add-EscapeCharacter ([string[]]$String) {
    # Escape periods in a string for RegEx
    $String -replace '\.','\.'
  }
  function Join-ByPrefix {
    param(
      [hashtable]$Hashtable,
      [PSCustomObject]$Object,
      [string]$Key,
      [string]$SubKey,
      [string]$Value
    )
    # Add IPv4 with matching octets to hashtable using matched octets as a prefix
    if (!$Hashtable.$Key.$SubKey) { $Hashtable.$Key[$SubKey] = [System.Collections.Generic.List[string]]@() }
    $Hashtable.$Key.$SubKey.Add(($Value -replace "$SubKey\.",$null))
  }
  function Submit-IoaRule {
    param(
      [string]$String,
      [int32]$DispositionId,
      [string]$Severity,
      [string]$GroupId
    )
    # Create a Custom IOA rule from the provided IPv4 address/range
    $Action = switch ($DispositionId) {
      10 { 'Monitor' }
      20 { 'Detect' }
      30 { 'Block' }
    }
    $Param = @{
      Name = ($Action,$String -join ' ')
      Description = (Show-FalconModule).UserAgent
      PatternSeverity = $Severity
      RuleTypeId = 9
      RuleGroupId = $GroupId
      DispositionId = $DispositionId
      FieldValue = @(
        [PSCustomObject]@{
          name = 'RemoteIPAddress'
          label = 'Remote IP Address'
          type = 'excludable'
          values = @(@{ label = 'include'; value = (Add-EscapeCharacter $String) })
        },
        [PSCustomObject]@{
          name = 'RemotePort'
          label = 'Remote TCP/UDP Port'
          type = 'excludable'
          values = @(@{ label = 'include'; value = '.*' })
        },
        [PSCustomObject]@{
          name = 'ConnectionType'
          label = 'Connection Type'
          type = 'set'
          values = @()
        }
      )
    }
    $Req = New-FalconIoaRule @Param
    if ($Req) {
      Write-Host "Created '$($Req.name)'."
      $Req
    }
  }
  $Token = @{}
  @('ClientId','ClientSecret','Cloud','MemberCid').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
}
process {
  # Import IP addresses from text file
  $Import = try { Get-Content $Path } catch { throw $_ }
  [PSCustomObject[]]$OctetList = @($Import).foreach{
    if ($_ -match '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])') {
      # Split valid IPv4 addresses into objects containing individual octets
      $i = ($_).Split('.',4)
      [PSCustomObject]@{octet1=$i[0];octet2=$i[1];octet3=$i[2];octet4=$i[3]}
    } else {
      Write-Error "'$_' is not a valid IPv4 address."
    }
  }
  if (!$OctetList) { throw "No valid IPv4 addresses found."}
  # Create hashtable to contain RegEx pattern content and group addresses when they share the first 2 or 3 octets
  $IoaList = @{ Match3 = @{}; Match2 = @{}; Match1 = [System.Collections.Generic.List[string]]@() }
  [PSCustomObject[]]$Match3 = @($OctetList | Group-Object -Property octet1,octet2,octet3).Where({
    $_.Count -gt 1}).Group
  [PSCustomObject[]]$Match2 = @($OctetList | Group-Object -Property octet1,octet2).Where({$_.Count -gt 1}).Group
  foreach ($i in $OctetList) {
    $IPv4 = $i.PSObject.Properties.Value -join '.'
    if (@($Match3).Where({$_.octet1 -eq $i.octet1 -and $_.octet2 -eq $i.octet2 -and $_.octet3 -eq $i.octet3})) {
      # Capture IPv4 addresses that share the first 3 octets
      Join-ByPrefix $IoaList $i Match3 ($i.octet1,$i.octet2,$i.octet3 -join '.') $IPv4
    } elseif (@($Match2).Where({$_.octet1 -eq $i.octet1 -and $_.octet2 -eq $i.octet2})) {
      # Capture IPv4 addresses that share the first 2 octets
      Join-ByPrefix $IoaList $i Match2 ($i.octet1,$i.octet2 -join '.') $IPv4
    } else {
      # Capture unique IPv4 addresses
      $IoaList.Match1.Add($IPv4)
    }
  }
  try {
    # Authenticate with CID
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      # Create IOA rule group
      $Group = try { New-FalconIoaGroup -Name $GroupName -Platform $Platform } catch { throw $_ }
      if ($Group.id) {
        $Group.rules = [System.Collections.Generic.List[object]]@()
        foreach ($Key in ('Match3','Match2')) {
          if ($IoaList.$Key.Keys) {
            # Create rules for IPv4 addresses with 3 and 2 shared octets
            @($IoaList.$Key.Keys | Sort-Object).foreach{
              $Req = Submit-IoaRule ($_,
                "($($IoaList.$Key.$_ -join '|'))" -join '.') $DispositionId $Severity $Group.id
              if ($Req) {
                # Enable rule and add to list for later modification
                $Req.enabled = $true
                $Group.rules.Add($Req)
              }
            }
          }
        }
        if ($IoaList.Match1) {
          # Create rules for unique IPv4 addresses
          @($IoaList.Match1 | Sort-Object).foreach{
            $Req = Submit-IoaRule $_ $DispositionId $Severity $Group.id
            if ($Req) {
              # Enable rule and add to list for later modification
              $Req.enabled = $true
              $Group.rules.Add($Req)
            }
          }
        }
      }
      
      if ($Group.rules) {
        # Enable IOA rules and rule group
        if ($Group.enabled -eq $false) { $Group.enabled = $true }
        @($Group | Edit-FalconIoaRule).foreach{
          @($_.rules).Where({$_.enabled -eq $true}).foreach{ Write-Host "Enabled IOA rule '$($_.name)'." }
        }
        $Enable = $Group | Edit-FalconIoaGroup
        if ($Enable -and $Enable.enabled -eq $true) {
          Write-Host "Enabled $($Enable.platform) IOA group '$($Enable.name)'."
        }
      }
    }
  } catch {
    Write-Error $_
  } finally {
    # Remove authentication token
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
  }
}