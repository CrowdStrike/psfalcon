#Requires -Version 5.1
<#
.SYNOPSIS
Output a list of different 'prevention_settings' between a source and target Prevention policy
.PARAMETER Source
Source policy
.PARAMETER Target
Target policy
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidateScript({
    [string[]]$Missing = foreach ($i in ('id','name','platform_name','prevention_settings')) { if (!$_.$i) { $i }}
    if ($Missing) { throw ('"Source" missing required property "{0}"' -f ($Missing -join ',')) } else { $true }
  })]
  [object]$Source,
  [Parameter(Mandatory,Position=2)]
  [ValidateScript({
    [string[]]$Missing = foreach ($i in ('id','name','platform_name','prevention_settings')) { if (!$_.$i) { $i }}
    if ($Missing) { throw ('"Target" missing required property "{0}"' -f ($Missing -join ',')) } else { $true }
  })]
  [object]$Target
)
process {
  if ($Source.platform_name -ne $Target.platform_name) {
    throw 'Unable to compare policies with different "platform_name" values!'
  }
  [PSCustomObject[]]$Output = @($Source.prevention_settings.settings).foreach{
    # Select appropriate sub-property under 'value' by setting 'type' and compare source setting to target setting
    [string[]]$Select = if ($_.type -eq 'mlslider') { 'detection','prevention' } else { 'configured','enabled' }
    $Ref = $_ | Select-Object id,description,@{l='value';e={$_.value | Select-Object $Select |
      ConvertTo-Json -Compress}}
    $Compare = @($Target.prevention_settings.settings).Where({$_.id -eq $Ref.id}) | Select-Object id,@{l='value';
      e={$_.value | Select-Object $Select | ConvertTo-Json -Compress}}
    if ($Ref.value -ne $Compare.value) {
      # If source and target settings do not match, output object
      [PSCustomObject]@{
        cid = $Target.cid
        policy_id = $Target.id
        id = $Ref.id
        description = $Ref.description
        source = $Ref.value
        target = $Compare.value
      }
    }
  }
  if ($Output) { $Output } else { Write-Host "No differences found between 'prevention_settings'." }
}