#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
using module @{ModuleName='ImportExcel';ModuleVersion='7.8'}
<#
.SYNOPSIS
Create an Excel-based pie chart displaying the number of end-of-life operating systems in your environment
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Hostname
CrowdStrike API hostname
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
  [string]$Hostname
)
begin {
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','Cloud').foreach{
  if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  Request-FalconToken @Token
}
process {
  Write-Host "Retrieving list of end-of-life assets..."
  [object[]]$EolAsset = Get-FalconAsset -Filter "os_is_eol:'Yes'" -Detailed -All |
    Select-Object id,cid,aid,os_version,kernel_version
  if (!$EolAsset) { throw "No end-of-life assets found." }
  [PSCustomObject[]]$Output = foreach ($OsVersion in ($EolAsset.os_version | Select-Object -Unique)) {
    foreach ($KernelVersion in ($EolAsset.Where({ $_.os_version -eq $OsVersion }).kernel_version |
    Select-Object -Unique )) {
      [PSCustomObject]@{
        OsVersion = ($OsVersion,$KernelVersion -join ' ')
        Count = ($EolAsset | Where-Object { $_.os_version -eq $OsVersion -and $_.kernel_version -eq
          $KernelVersion } | Measure-Object).Count
      }
    }
  }
  if (!$Output) { throw "Failed to count 'os_version' and 'kernel_version'." }
  $ChartDef = @{
    Title = 'End of Life OS Counts'
    ChartType = 'Pie3D'
    XRange = 'OSVersion'
    YRange = 'Count'
    TitleBold = $true
    TitleSize = 28
    Width = 1600
    Height = 1000
    Column = 1
    Row = 1
    ShowPercent = $true
    LegendPosition = 'Bottom'
    LegendBold = $true
  }
  $Export = @{
    Path = "$(Join-Path (Get-Location).Path (Get-Date -f yyyy-MM-dd-HHmmss)).xlsx"
    ExcelChartDefinition = New-ExcelChartDefinition @ChartDef
    AutoNameRange = $true
    WorksheetName = 'EolOS'
    StartRow = 55
  }
  $Output | Export-Excel @Export
}
end { if (Test-Path $Export.Path) { Get-ChildItem $Export.Path | Select-Object FullName,Length,LastWriteTime }}