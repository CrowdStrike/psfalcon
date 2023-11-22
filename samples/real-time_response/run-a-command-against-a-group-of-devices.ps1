#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Search for a Host Group by name, execute a command on the members of the group using Real-time Response and output
results to CSV
.PARAMETER GroupName
Host group name
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER QueueOffline
Add non-responsive hosts to the offline queue
#>
param(
  [Parameter(Mandatory,Position=1)]
  [string]$GroupName,
  [Parameter(Mandatory,Position=2)]
  [string]$Command,
  [Parameter(Position=3)]
  [string]$Argument,
  [boolean]$QueueOffline
)
# Find group identifier using 'name' filter
$GroupId = Get-FalconHostGroup -Filter "name:'$($GroupName.ToLower())'"
if (!$GroupId) { throw "No host group found matching '$($GroupName.ToLower())'." }

# Set CSV output file name and baseline Invoke-FalconRtr parameters
$OutputFile = Join-Path (Get-Location).Path "$('rtr',($Command -replace ' ','_'),$GroupId -join '_').csv"
$Param = @{ GroupId = $GroupId }

# Add Command/Argument/QueueOffline status
switch ($PSBoundParameters.Keys) {{ $_ -ne 'GroupName' } { $Param[$_] = $PSBoundParameters.$_ }}

# Use 'Invoke-FalconRtr' and output result to CSV
Invoke-FalconRtr @Param | Export-Csv -Path $OutputFile
if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }