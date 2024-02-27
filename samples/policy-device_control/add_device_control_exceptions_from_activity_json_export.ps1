#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Add a list of exceptions to an existing Device Control policy using a Json export from the 'Device Control
Activity' page within the Falcon console.
.DESCRIPTION
Your Json file must contain 'platform_name', 'policy_action', 'usb_device_classes' and either 'usb_device_id' or
'usb_device_vendor_id', 'usb_device_product_id', and 'usb_device_sn' to function. If the required fields are not
present, the script will generate an error and will not continue.

Once complete, the script will create an 'exception_invalid' and 'exception_valid' CSV files with lists of the
exceptions that were processed (with an 'added' column stating whether or not they were created) and exceptions
that were ignored.

Requires 'Device control policies: Read' and 'Device control policies: Write' permission.
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Path
Path to Json export
.PARAMETER Class
Class type, for filtering Json to specific exceptions
.PARAMETER Action
Action type, used when creating exceptions
.PARAMETER PolicyId
Device Control policy to add exceptions
.EXAMPLE
.\add_device_control_exceptions_from_activity_export_json.ps1 -ClientId <client_id> -ClientSecret <client_secret>
  -Cloud us-1 -Path .\my.json -Class MASS_STORAGE -Action FULL_ACCESS -PolicyId <id>
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(Position=3)]
  [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
  [string]$Cloud,
  [Parameter(Mandatory,Position=4)]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$Path,
  [Parameter(Mandatory,Position=5)]
  [ValidateSet('ANY','AUDIO_VIDEO','IMAGING','MASS_STORAGE','MOBILE','PRINTER','WIRELESS',IgnoreCase=$false)]
  [string]$Class,
  [Parameter(Mandatory,Position=6)]
  [ValidateSet('BLOCK_ALL','BLOCK_EXECUTE','BLOCK_WRITE_EXECUTE','FULL_ACCESS',IgnoreCase=$false)]
  [string]$Action,
  [Parameter(Mandatory,Position=7)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$PolicyId
)
begin {
  if (($Class -eq 'ANY' -and $Action -eq 'FULL_ACCESS') -or ($Class -match
  'AUDIO_VIDEO|IMAGING|MOBILE|PRINTER|WIRELESS' -and $Action -notmatch 'BLOCK_ALL|FULL_ACCESS')) {
    # Error if user attempts unsupported action for chosen class
    throw "'$Action' is not an accepted action value for class '$Class'."
  } else {
    # Define names of output files and request authorization token
    [string]$InvalidPath = Join-Path (Get-Location).Path 'exception_invalid.csv'
    [string]$ValidPath = Join-Path (Get-Location).Path 'exception_valid.csv'
    $Token = @{ ClientId = $ClientId; ClientSecret = $ClientSecret }
    if ($Cloud) { $Token['Cloud'] = $Cloud }
    Request-FalconToken @Token
  }
}
process {
  if ((Test-FalconToken).Token -eq $true) {
    try {
      # Import Json and select required fields
      $Import = Get-Content -Path $Path | ConvertFrom-Json | Where-Object { $_.usb_device_classes -contains
        $Class } | Select-Object usb_device_id,usb_device_vendor_id,usb_device_product_id,usb_device_sn,
        usb_device_vendor_name,usb_device_product_name
      if ($Import) {
        # Create hashtable to contain valid and invalid entries
        $Output = @{
          Invalid = [System.Collections.Generic.List[PSCustomObject]]@()
          Valid = [System.Collections.Generic.List[PSCustomObject]]@()
        }
        foreach ($i in $Import) {
          if (![string]::IsNullOrEmpty($i.usb_device_id)) {
            if ($i.usb_device_id -notmatch '^(\w+_){2}\w+' -or $i.usb_device_id -match
            '[^\x00-\x7F]|^(\w+_){2}.+_') {
              # Capture invalid usb_device_id values
              if ($Output.Invalid.usb_device_id -notcontains $i.usb_device_id) { $Output.Invalid.Add($i) }
            } elseif ($Output.Valid.combined_id -notcontains ($i.usb_device_id).Trim()) {
              # Capture unique entries with usb_device_id values and convert them to exception format
              $Output.Valid.Add([PSCustomObject]@{
                action = $Action
                combined_id = ($i.usb_device_id).Trim()
                vendor_name = ($i.usb_device_vendor_name).Trim()
                product_name = ($i.usb_device_product_name).Trim()
              })
            }
          } else {
            [boolean[]]$Missing = @('usb_device_vendor_id','usb_device_product_id','usb_device_sn').foreach{
              # Verify required fields
              [string]::IsNullOrEmpty($i.$_)
            }
            if ($Missing -eq $true) {
              # Capture entries that don't have required fields
              if ($Output.Invalid.usb_device_id -notcontains $i.usb_device_id) { $Output.Invalid.Add($i) }
            } else {
              $Existing = $Output.Valid | Where-Object { $_.vendor_id -eq ($i.usb_device_vendor_id).Trim() -and
                $_.product_id -eq ($i.usb_device_product_id).Trim() -and $_.serial_number -eq
                ($i.usb_device_sn).Trim() }
              if (!$Existing) {
                # Capture unique usb_device_vendor_id/usb_device_product_id/usb_device_sn entries and convert them
                # to exception format
                $Output.Valid.Add([PSCustomObject]@{
                  action = $Action
                  vendor_id = ($i.usb_device_vendor_id).Trim()
                  product_id = ($i.usb_device_product_id).Trim()
                  serial_number = ($i.usb_device_sn).Trim()
                  vendor_name = ($i.usb_device_vendor_name).Trim()
                  product_name = ($i.usb_device_product_name).Trim()
                })
              }
            }
          }
        }
        if ($Output.Valid) {
          $Setting = [PSCustomObject]@{ classes = @(@{ id = $Class; exceptions = $Output.Valid })}
          $Edit = Edit-FalconDeviceControlPolicy -Id $PolicyId -Setting $Setting
          if ($Edit) {
            foreach ($i in $Edit.settings.classes.Where({ $_.id -eq $Class }).exceptions) {
              if ($i.combined_id) {
                # Mark each combined_id as added
                @(@($Output.Valid).Where({ $_.combined_id -eq $i.combined_id })).foreach{
                  $_.PSObject.Properties.Add((New-Object PSNoteProperty('added',$true)))
                }
              } elseif ($i.vendor_id -and $i.product_id -and $i.serial_number) {
                # Mark each vendor_id/product_id/serial_number as added
                @(@($Output.Valid).Where({ $_.vendor_id -eq $i.vendor_id -and $_.product_id -eq $i.product_id -and
                $_.serial_number -eq $i.serial_number})).foreach{
                  $_.PSObject.Properties.Add((New-Object PSNoteProperty('added',$true)))
                }
              }
            }
            @($Output.Valid).Where({ !$_.added }).foreach{
              # Mark unmatched results with 'false'
              $_.PSObject.Properties.Add((New-Object PSNoteProperty('added',$false)))
            }
          }
          # Export results to CSV and display created files
          $Output.Valid | Export-Csv $ValidPath -NoTypeInformation
        }
        if ($Output.Invalid) { $Output.Invalid | Export-Csv $InvalidPath -NoTypeInformation }
        @($ValidPath,$InvalidPath).foreach{
          if (Test-Path $_) { Get-ChildItem $_ | Select-Object FullName,Length,LastWriteTime }
        }
      }   
    } catch {
      throw $_
    }
  }
}