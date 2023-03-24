#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
param(
    [Parameter(Mandatory)]
    [string]$Filename
)
[string]$OutputFile = Join-Path (Get-Location).Path "hidden_detections_$(Get-Date -Format FileDateTime).txt"
if ($null -eq (Get-FalconDetection -Filter "behaviors.filename:'$Filename'" -Total)) {
    # Generate error if no detections are found for $Filename
    throw "No detections found for '$Filename'."
}
do {
    # Retrieve 1,000 detections and hide them until none are left
    if ($Id) { Start-Sleep -Seconds 5 }
    $Edit = Get-FalconDetection -Filter "behaviors.filename:'$Filename'" -Limit 1000 -OutVariable Id |
        Edit-FalconDetection -ShowInUi $false
    if ($Edit.writes.resources_affected) {
        # Notify of hidden detections and output detection_id values to text file
        Write-Host ('Hid {0} detection(s)...' -f $Edit.writes.resources_affected)
        $Id >> $OutputFile
    }
} while ($Id)
if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }