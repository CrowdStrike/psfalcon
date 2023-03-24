#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
**NOTE**: This script expects a text file that contains case-sensitive hostnames (one per line) in `-Path`.
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId
)
# Error if host group does not exist
if (!(Get-FalconHostGroup -Id $GroupId)) { throw "No host group found matching '$GroupId'." }

# Use 'Find-FalconHostname' to match list and add hosts to host group
Find-FalconHostname -Path $Path -OutVariable HostList | Invoke-FalconHostGroupAction -Name add-hosts -Id $GroupId

# Error if 'Find-FalconHostname' found no matches
if (!$HostList.hostname) { throw "No hosts found." }