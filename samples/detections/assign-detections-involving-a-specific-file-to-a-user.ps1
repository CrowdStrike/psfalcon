#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Assign all detections involving a specific filename to a user (by username)
.PARAMETER Username
User name, used for assignment of detections
.PARAMETER Filename
Filename, used to filter detections
#>
param(
  [Parameter(Mandatory,Position=1)]
  [string]$Username,
  [Parameter(Mandatory,Position=2)]
  [string]$Filename
)
# Get User identifier
$Uuid = Get-FalconUser -Username $Username -EA 0
if (!$Uuid) { throw "No user identifier found for '$Username'." }

if (!(Get-FalconDetection -Filter "behaviors.filename:'$Filename'")) {
  # Generate error if no detections are found for $Filename
  throw "No detections found for '$Filename'."
}
do {
  # Retrieve 1,000 detections that are not assigned and assign them until none are left
  if ($Id) { Start-Sleep -Seconds 5 }
  $Param = @{
    Filter = "behaviors.filename:'$Filename'+assigned_to_uuid:!'$Uuid'"
    Limit = 1000
    OutVariable = 'Id'
  }
  $Edit = Get-FalconDetection @Param | Edit-FalconDetection -AssignedToUuid $Uuid
  if ($Edit.writes.resources_affected) {
    Write-Host ('Assigned {0} detection(s) to {1}...' -f $Edit.writes.resources_affected,$Uuid)
  }
} while ($Id)