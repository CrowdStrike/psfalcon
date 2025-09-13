#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
List SERVICE_ACCESS events in Falcon Identity Protection filtered by Service and/or Protocol
.PARAMETER Service
Service type to filter
.PARAMETER Protocol
Protocol type to filter
.EXAMPLE
.\service-access-event-query.ps1 -Service COMPUTER_ACCESS -Protocol KERBEROS
#>
param(
  [Parameter(Position=1)]
  [ValidateSet('COMPUTER_ACCESS','DB','DNS','FILE_SHARE','GENERIC_CLOUD','LDAP','MAIL','NTLM','RPCSS',
    'REMOTE_DESKTOP','SCCM','SIP','SERVICE_ACCOUNT','UNKNOWN','WEB',IgnoreCase=$false)]
  [string[]]$Service,
  [Parameter(Position=2)]
  [ValidateSet('DCE_RPC','KERBEROS','LDAP','NTLM','SSL','UNKNOWN',IgnoreCase=$false)]
  [string[]]$Protocol
)
process {
  # Build 'activityQuery' with Service and/or Protocol
  if (!$Service -and !$Protocol) { throw "Service or Protocol must be provided." }
  [System.Collections.Generic.List[string]]$Activity = @('all:{')
  if ($Service) { $Activity.Add("targetServiceTypes:[$($Service -join ',')]") }
  if ($Protocol) { $Activity.Add("protocolTypes:[$($Protocol -join ',')]") }
  $Activity.Add('}')
  $String = 'query($after:Cursor){timeline(types:[SERVICE_ACCESS],first:1000,sortOrder:DESCENDING,activityQuery:' +
    '{' + ($Activity -join ' ') + '},after:$after){nodes{timestamp,eventType,eventLabel,...on TimelineServiceAcc' +
    'essEvent{protocolType,ipAddress,userEntity{primaryDisplayName,secondaryDisplayName},targetEndpointEntity{ho' +
    'stName,lastIpAddress}}}pageInfo{hasNextPage,endCursor}}}'
  try {
    $Request = Invoke-FalconIdentityGraph -String $String -All
    if ($Request.timeline.nodes) {
      # List events under 'timeline' and 'nodes'
      $Request.timeline.nodes
    } else {
      # Write error when no results are found
      [System.Collections.Generic.List[string]]$Message = @('No results found for')
      if ($Service) { $Message.Add(('Service "{0}"' -f ($Service -join ','))) }
      if ($Service -and $Protocol) { $Message.Add('and') }
      if ($Protocol) { $Message.Add(('Protocol "{0}"' -f ($Protocol -join ','))) }
      throw "$($Message -join ' ')."
    }
  } catch {
    throw $_
  }
}