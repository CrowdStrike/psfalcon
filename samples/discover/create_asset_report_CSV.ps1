#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a CSV containing asset details for a list of hostnames
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Hostname
CrowdStrike API hostname
.PARAMETER HostList
Path to a text file containing a list of hostnames, one on each line
.NOTES
Original script written by Reddit user some_rando966
.EXAMPLE
.\create_asset_report.CSV.ps1 -ClientId foo -ClientSecret bar -Cloud us-1 -HostList .\name.txt
#>
[CmdletBinding(DefaultParameterSetName='Cloud')]
param(
  [Parameter(ParameterSetName='Cloud',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
  [Parameter(ParameterSetName='Hostname',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(ParameterSetName='Cloud',Mandatory,ValueFromPipelineByPropertyName,Position=2)]
  [Parameter(ParameterSetName='Hostname',Mandatory,ValueFromPipelineByPropertyName,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=3)]
  [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
  [string]$Cloud,
  [Parameter(ParameterSetName='Hostname',ValueFromPipelineByPropertyName,Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname,
  [Parameter(ParameterSetName='Cloud',Position=4)]
  [Parameter(ParameterSetName='Hostname',Position=4)]
  [ValidateScript({
  if (Test-Path -Path $_ -PathType Leaf) {
    $true
  } else {
    throw "Cannot find path '$_' because it does not exist or is a directory."
  }
  })]
  [string]$HostList
)
begin {
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','Cloud').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  [string]$Output = "asset_report_$(Get-Date -Format FileDateTime).csv"
}
process {
  Request-FalconToken @Token
  if ((Test-FalconToken).token -eq $true) {
    @(Get-Content $HostList).Where({ ![string]::IsNullOrWhiteSpace($_) }).foreach{
      # Retrieve detail from Discover for the most recently seen result based on hostname match
      $AssetObj = Get-FalconAsset -Filter "hostname:'$_'" -Sort last_seen_timestamp.desc -Limit 1 -Detailed |
        Select-Object id,aid,hostname,entity_type,system_serial_number,encryption_status,total_disk_space,
        used_disk_space,available_disk_space,system_product_name
      if ($AssetObj) {
        # Retrieve required fields from most recent successful user login
        $LoginObj = Get-FalconAsset -Filter "host_id:'$($AssetObj.id)'+login_status:'Successful'" -Sort (
          'login_timestamp.desc') -Login -Detailed | Where-Object { $_.username -notmatch
          "defaultuser.*|DefaultAppPool" } | Select-Object username,login_timestamp,login_status,host_city,
          host_country -First 1
        if (!$LoginObj) { Write-Warning "No login history found for '$_'." }
        if ($AssetObj.entity_type -eq 'managed') {
          # If host is managed, add in Device API detail
          $HostObj = Get-FalconHost -Id $AssetObj.aid | Select-Object os_version,status,first_seen,last_seen
        } else {
          Write-Warning "Asset '$_' is unmanaged. Some data may be absent from final output."
        }
        # Output selected fields to CSV
        [PSCustomObject]@{
          hostname = $AssetObj.hostname
          os_version = $HostObj.os_version
          system_serial_number = $AssetObj.system_serial_number
          encryption_status = $AssetObj.encryption_status
          containment_status = $HostObj.status
          total_disk_space = $AssetObj.total_disk_space
          used_disk_space = $AssetObj.used_disk_space
          available_disk_space = $AssetObj.available_disk_space
          system_product_name = $AssetObj.system_product_name
          host_first_seen = $HostObj.first_seen
          host_last_seen = $HostObj.last_seen
          last_login_username = $LoginObj.username
          last_login_timestamp = $LoginObj.login_timestamp
          last_login_status = $LoginObj.login_status
          last_login_host_city = $LoginObj.host_city
          last_login_host_country = $LoginObj.host_country
        } | Export-Csv $Output -NoTypeInformation -Append
      } else {
        Write-Warning "No asset found matching '$_'."
      }
    }
  }
}
end {
  if (Test-Path $Output) { Get-ChildItem $Output | Select-Object FullName,Length,LastWriteTime }
}