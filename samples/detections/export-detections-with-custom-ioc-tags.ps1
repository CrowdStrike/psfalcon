#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a Json output of detections involving a Custom IOC, and include the user-defined tags with those IOCs
#>
[string]$OutputFile = Join-Path (Get-Location).Path "custom_ioc_detections_$(Get-Date -Format FileDateTime).json"
try {
  # Retrieve all 'CustomIOC' detections
  [object[]]$Detection = Get-FalconDetection -Filter "behaviors.display_name:*'CustomIOC*'" -Detailed -All
  if ($Detection) {
    # Create search filters for each detected Custom IOC and retrieve type, value, and tags
    [string[]]$Filter = @($Detection.behaviors).foreach{
      "type:'$($_.ioc_type)'+value:'$($_.ioc_value)'"
    } | Select-Object -Unique
    [object[]]$IocList = @($Filter).foreach{
      Get-FalconIoc -Filter $_ -Detailed | Select-Object type,value,tags
    }
    foreach ($Ioc in $IocList) {
      # Append 'ioc_tags' to relevant detection(s)
      ($Detection | Where-Object {
        $_.behaviors.ioc_type -eq $Ioc.type -and $_.behaviors.ioc_value -eq $Ioc.value
      }).behaviors | ForEach-Object {
        $_.PSObject.Properties.Add((New-Object PSNoteProperty('ioc_tags',$Ioc.tags)))
      }
    }
    # Export detections to Json
    $Detection | ConvertTo-Json -Depth 16 >> $OutputFile
    if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
  }
} catch {
  throw $_
}