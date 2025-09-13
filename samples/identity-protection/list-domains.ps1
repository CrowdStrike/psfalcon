#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
List domains configured in Falcon Identity Protection
#>
try {
  $Request = Invoke-FalconIdentityGraph -String '{domains(dataSources:[])}'
  if ($Request.domains) { $Request.domains } else { throw "No configured domains." }
} catch {
  throw $_
}