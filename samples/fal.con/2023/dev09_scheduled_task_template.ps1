#Requires -Version 5.1
using module @{ModuleName='Microsoft.PowerShell.SecretStore';ModuleVersion='1.0'}
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
A script template to demonstrate the retrieval of API client credentials from Microsoft.PowerShell.SecretStore,
request an authorization token from the CrowdStrike Falcon APIs and run pre-determined code
.PARAMETER SecretName
Name of the secret stored in the SecretVault
.NOTES
Installation and configuration of the SecretStore module is described here:
https://github.com/CrowdStrike/psfalcon/wiki/Authentication#securing-credentials

A scheduled task designed to run this script will look something like this:
[x] Run whether user is logged on or not
[x] Do not store password. The task will only have access to local computer resources.

Trigger:
One time - At 08:00AM on 01/01/2024 - After triggered, repeat every 24 hours

Action:
Start a program - powershell.exe -c C:\path\to\dev09_scheduled_task_template.ps1 -SecretName MySecret
.EXAMPLE
.\dev09_scheduled_task_template.ps1 -SecretName MySecret
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [string]$SecretName
)
process {
  try {
    # Retrieve secret as a hashtable
    [hashtable]$Secret = Get-Secret -Name $SecretName -AsPlainText
    if ($Secret) {
      # Request an authorization token from the Falcon APIs
      Request-FalconToken @Secret
      if ((Test-FalconToken).Token -eq $true) {
        # Remove example and add code to run here
        (Get-Date -Format 'yyyy-MM-dd hh:mm:ss'),
          'token_retrieved' -join ': ' >> $HOME\Desktop\dev09_scheduled_task_template.log
      }
    }
  } catch {
    throw $_
  } finally {
    # Silently revoke active authorization token
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
  }
}