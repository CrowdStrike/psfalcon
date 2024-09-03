#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create a CSV that replicates the 'Sensor Policy Daily Report' in the Falcon UI
.PARAMETER Path
Path to CSV file to create
.NOTES
Requires 'Device Control Policies: Read', 'Host Groups: Read', 'Hosts: Read', 'Prevention Policies: Read', and
'Sensor Update Policies: Read' permission.
#>
param(
  [Parameter(Mandatory)]
  [ValidatePattern('\.csv$')]
  [ValidateScript({
    if ((Test-Path $_) -eq $true) { throw "The file '$_' already exists." } else { $true }
  })]
  [string]$Path
)
$Info = @{
  # Gather policy/group details to add relevant 'name' and 'description' to output
  device_control = @(Get-FalconDeviceControlPolicy -Detailed -All | Select-Object id,name,description)
  groups = @(Get-FalconHostGroup -Detailed -All | Select-Object id,name)
  prevention = @(Get-FalconPreventionPolicy -Detailed -All | Select-Object id,name,description)
  sensor_update = @(Get-FalconSensorUpdatePolicy -Detailed -All | Select-Object id,name,description)
}
$Select = @(
  # Select fields and label to match report
  @{label='Host Name';expression={$_.hostname}},
  @{label='Platform';expression={$_.platform_name}},
  @{label='OS Version';expression={$_.os_version}},
  @{label='AgentVersion';expression={$_.agent_version}},
  @{label='First Seen (UTC)';expression={$_.first_seen}},
  @{label='Last Seen (UTC)';expression={$_.last_seen}},
  @{label='Groups';expression={
    (@($_.groups).foreach{
      $Info.groups | Where-Object id -eq $_ | Select-Object -ExpandProperty name
    }) -join ', '
  }},
  @{label='No. of Groups';expression={($_.groups | Measure-Object).Count}},
  @{label='Sensor Update Policy Name';expression={
    $Info.sensor_update | Where-Object id -eq $_.device_policies.sensor_update.policy_id |
      Select-Object -ExpandProperty name
  }},
  @{label='Sensor Update Policy Description';expression={
    $Info.sensor_update | Where-Object id -eq $_.device_policies.sensor_update.policy_id |
      Select-Object -ExpandProperty description
  }},
  @{label='Sensor Update Policy Applied Date';expression={$_.device_policies.sensor_update.applied_date}},
  @{label='Prevention Policy Name';expression={
    $Info.prevention | Where-Object id -eq $_.device_policies.prevention.policy_id |
      Select-Object -ExpandProperty name
  }},
  @{label='Prevention Policy Description';expression={
    $Info.prevention | Where-Object id -eq $_.device_policies.prevention.policy_id |
      Select-Object -ExpandProperty description
  }},
  @{label='Prevention Policy Applied Date';expression={$_.device_policies.prevention.applied_date}},
  @{label='Device Control Policy Name';expression={
    $Info.device_control | Where-Object id -eq $_.device_policies.device_control.policy_id |
      Select-Object -ExpandProperty name
  }},
  @{label='Device Control Policy Description';expression={
    $Info.device_control | Where-Object id -eq $_.device_policies.device_control.policy_id |
      Select-Object -ExpandProperty description
  }},
  @{label='Device Control Policy Applied Date';expression={$_.device_policies.device_control.applied_date}},
  @{label='aid';expression={$_.device_id}},
  @{label='Site Name';expression={$_.site_name}}
)
Get-FalconHost -Detailed -All | Select-Object $Select | Export-Csv -Path $Path -NoTypeInformation
if (Test-Path $Path) { Get-ChildItem $Path | Select-Object FullName,Length,LastWriteTime }