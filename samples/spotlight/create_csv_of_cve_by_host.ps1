#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS

.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER Hostname
Hostname value, used with authorization token request [default: https://api.crowdstrike.com]
.PARAMETER MemberCid
Optional child CID, if requesting an authorization token for a single child CID
.PARAMETER Cve
One or more CVE values
.EXAMPLE
.\create_csv_of_cve_by_host.ps1 -ClientId abc -ClientSecret def -Cve 'CVE-2024-0001','CVE-2024-0002'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname,
  [Parameter(Position=4)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$MemberCid,
  [Parameter(Mandatory,Position=5)]
  [string[]]$Cve
)
begin {
  # Build hashtable for authorization token request
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','MemberCid').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  # Define filename for CSV output
  $OutputFile = Join-Path (Get-Location).Path (('cve_by_host',
    (Get-Date -Format FileDate) -join '_'),'csv' -join '.')
}
process {
  try {
    if (Test-Path $OutputFile) { throw "'$OutputFile' already exists." }
    # Request an authorization token from the Falcon APIs
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      for ($i=0; $i -lt ($PSBoundParameters.Cve).Count; $i+=20) {
        # Retrieve 20 CVEs at a time from Spotlight using a filter and include 'host_info'
        [string]$Group = (@($PSBoundParameters.Cve[$i..($i+19)]).foreach{ "'$_'" }) -join ','
        $Param = @{
          Filter = "suppression_info.is_suppressed:False+status:!'closed'+cve.id:[$Group]"
          Facet = 'host_info'
          Detailed = $true
          All = $true
          Verbose = $true
        }
        [PSCustomObject[]]$Output = Get-FalconVulnerability @Param | Select-Object id,vulnerability_id,status,
          confidence,created_timestamp,updated_timestamp,aid,@{l='hostname';e={$_.host_info.hostname}},
          @{l='last_login_user';e={''}},@{l='last_login_timestamp';e={''}}
        if ($Output) {
          # Retrieve recent login activity for unique 'aid' values
          $IdList = $Output.aid | Select-Object -Unique
          $LoginList = Get-FalconHost -Id $IdList -Login
          if ($LoginList) {
            foreach ($Id in $IdList) {
              @($Output).Where({$_.aid -eq $Id}).foreach{
                # Update 'last_login_user' and 'last_login_timestamp'
                $Login = @($LoginList).Where({$_.device_id -eq $Id}).recent_logins
                $_.last_login_user = $Login.user_name
                $_.last_login_timestamp = $Login.login_time
              }
            }
          }
        }
        # Output to CSV
        $Output | Export-Csv -Path $OutputFile -NoTypeInformation -Append
      }
      if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
    }
  } catch {
    throw $_
  } finally {
    # Silently revoke active authorization token
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
  }
}