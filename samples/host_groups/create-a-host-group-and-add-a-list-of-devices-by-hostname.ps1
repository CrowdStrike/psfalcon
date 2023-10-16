#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create a host group, ingest a list of hostnames from a text file and add the corresponding hosts to the group
.PARAMETER Path
Path to a list of hostnames (one per line)
.PARAMETER Name
Name of host group to create
.PARAMETER Description
Description of the host group to create
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('\.txt$')]
  [ValidateScript({
    if (Test-Path -Path $_ -PathType Leaf) {
      $true
    } else {
      throw "Cannot find path '$_' because it does not exist or is a directory."
    }
  })]
  [string]$Path,
  [Parameter(Mandatory,Position=2)]
  [string]$Name,
  [Parameter(Position=3)]
  [string]$Description
)
# Create host group
$Param = @{ GroupType = 'static'; Name = $Name }
if ($Description) { $Param['Description'] = $Description }
$Group = New-FalconHostGroup @Param
if (!$Group) { throw "Failed to create host group. Check permissions." }

# Use Find-FalconDuplicate to find hosts and add them to the new group
Find-FalconHostname -Path $Path -OutVariable HostList | Invoke-FalconHostGroupAction -Name add-hosts -Id $Group.id
if (!$HostList) { throw "No hosts found." }