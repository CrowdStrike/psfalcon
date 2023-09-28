#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a series of CSVs containing the policies, rule groups and rules from Falcon Firewall Management
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER MemberCid
Member CID, used when authenticating within a multi-CID environment (Falcon Flight Control)
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Hostname
CrowdStrike API hostname
#>
[CmdletBinding(DefaultParameterSetName='Cloud')]
param(
  [Parameter(ParameterSetName='Cloud',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
  [Parameter(ParameterSetName='Hostname',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(ParameterSetName='Cloud',Mandatory,ValueFromPipelineByPropertyName,Position=2)]
  [Parameter(ParameterSetName='Hostname',Mandatory,ValueFromPipelineByPropertyName,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=3)]
  [Parameter(ParameterSetName='Hostname',ValueFromPipelineByPropertyName,Position=3)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$MemberCid,
  [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=4)]
  [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
  [string]$Cloud,
  [Parameter(ParameterSetName='Hostname',ValueFromPipelineByPropertyName,Position=4)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname
)
begin {
  # Create hashtable to request authorization token
  $Token = @{}
  @('ClientId','ClientSecret','MemberCid','Cloud','Hostname').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  # Log file names
  [string]$PolicyPath = Join-Path (Get-Location).Path "firewall_policy$(
    if ($MemberCid) { "$($MemberCid)_" } else { '_' })$(Get-Date -Format FileDateTime).csv"
  [string]$GroupPath = Join-Path (Get-Location).Path "firewall_group$(
    if ($MemberCid) { "$($MemberCid)_" } else { '_' })$(Get-Date -Format FileDateTime).csv"
  [string]$RulePath = Join-Path (Get-Location).Path "firewall_rule$(
    if ($MemberCid) { "$($MemberCid)_" } else { '_' })$(Get-Date -Format FileDateTime).csv"
}
process {
  try {
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      # Create CSV for policies
      Get-FalconFirewallPolicy -Include settings -Detailed -All |
        Select-Object cid,id,platform_name,enabled,name,
        @{label='host_groups';expression={$_.groups.id -join ','}},
        @{label='default_inbound';expression={$_.settings.default_inbound}},
        @{label='default_outbound';expression={$_.settings.default_outbound}},
        @{label='enforce';expression={$_.settings.enforce}},
        @{label='test_mode';expression={$_.settings.test_mode}},
        @{label='local_logging';expression={$_.settings.local_logging}},
        @{label='rule_groups';expression={$_.settings.rule_group_ids -join ','}},
        @{label='tracking';expression={$_.settings.tracking}},
        created_by,created_timestamp,modified_by,modified_timestamp | Export-Csv $PolicyPath -NoTypeInformation
      # Create CSV for rule groups
      Get-FalconFirewallGroup -Detailed -All |
        Select-Object @{label='cid';expression={$_.customer_id}},
        id,platform,name,enabled,deleted,
        @{label='policy_ids';expression={$_.policy_ids -join ','}},
        @{label='rule_ids';expression={$_.rule_ids -join ','}},
        created_by,created_on,modified_by,modified_on,tracking | Export-Csv $GroupPath -NoTypeInformation
      # Create CSV for rules
      Get-FalconFirewallRule -Detailed -All |
        Select-Object @{label='id';expression={$_.family}},
        @{label='rule_group_id';expression={$_.rule_group.id}},
        name,enabled,deleted,version,direction,action,address_family,
        @{label='protocol';expression={
          [string]$Label = switch ($_.protocol) {
            # Add protocol label using IANA protocol numbers
            '0' { 'HOPOP' }
            '1' { 'ICMP' }
            '2' { 'IGMP' }
            '3' { 'GGP' }
            '4' { 'IPv4' }
            '5' { 'ST' }
            '6' { 'TCP' }
            '7' { 'CBT' }
            '8' { 'EGP' }
            '9' { 'IGP' }
            '10' { 'BBN-RCC-MON' }
            '11' { 'NVP-II' }
            '12' { 'PUP' }
            '13' { 'ARGUS' }
            '14' { 'EMCON' }
            '15' { 'XNET' }
            '16' { 'CHAOS' }
            '17' { 'UDP' }
            '18' { 'MUX' }
            '19' { 'DCN-MEAS' }
            '20' { 'HMP' }
            '21' { 'PRM' }
            '22' { 'XNS-IDP' }
            '23' { 'TRUNK-1' }
            '24' { 'TRUNK-2' }
            '25' { 'LEAF-1' }
            '26' { 'LEAF-2' }
            '27' { 'RDP' }
            '28' { 'IRTP' }
            '29' { 'ISO-TP4' }
            '30' { 'NETBLT' }
            '31' { 'MFE-NSP' }
            '32' { 'MERIT-INP' }
            '33' { 'DCCP' }
            '34' { '3PC' }
            '35' { 'IDPR' }
            '36' { 'XTP' }
            '37' { 'DDP' }
            '38' { 'IDPR-CMTP' }
            '39' { 'TP++' }
            '40' { 'IL' }
            '41' { 'IPv6' }
            '42' { 'SDRP' }
            '43' { 'IPv6-Route' }
            '44' { 'IPv6-Frag' }
            '45' { 'IDRP' }
            '46' { 'RSVP' }
            '47' { 'GRE' }
            '48' { 'DSR' }
            '49' { 'BNA' }
            '50' { 'ESP' }
            '51' { 'AH' }
            '52' { 'I-NLSP' }
            '53' { 'SWIPE' }
            '54' { 'NARP' }
            '55' { 'MOBILE' }
            '56' { 'TLSP' }
            '57' { 'SKIP' }
            '58' { 'IPv6-ICMP' }
            '59' { 'IPv6-NoNxt' }
            '60' { 'IPv6-Opts' }
            '62' { 'CFTP' }
            '64' { 'SAT-EXPAK' }
            '65' { 'KRYPTOLAN' }
            '66' { 'RVD' }
            '67' { 'IPPC' }
            '69' { 'SAT-MON' }
            '70' { 'VISA' }
            '71' { 'IPCV' }
            '72' { 'CPNX' }
            '73' { 'CPHB' }
            '74' { 'WSN' }
            '75' { 'PVP' }
            '76' { 'BR-SAT-MON' }
            '77' { 'SUN-ND' }
            '78' { 'WB-MON' }
            '79' { 'WB-EXPAK' }
            '80' { 'ISO-IP' }
            '81' { 'VMTP' }
            '82' { 'SECURE-VMTP' }
            '83' { 'VINES' }
            '84' { 'IPTM' }
            '85' { 'NSFNET-IGP' }
            '86' { 'DGP' }
            '87' { 'TCF' }
            '88' { 'EIGRP' }
            '89' { 'OSPFIGP' }
            '90' { 'Sprite-RPC' }
            '91' { 'LARP' }
            '92' { 'MTP' }
            '93' { 'AX.25' }
            '94' { 'IPIP' }
            '95' { 'MICP' }
            '96' { 'SCC-SP' }
            '97' { 'ETHERIP' }
            '98' { 'ENCAP' }
            '100' { 'GMTP' }
            '101' { 'IFMP' }
            '102' { 'PNNI' }
            '103' { 'PIM' }
            '104' { 'ARIS' }
            '105' { 'SCPS' }
            '106' { 'QNX' }
            '107' { 'A/N' }
            '108' { 'IPComp' }
            '109' { 'SNP' }
            '110' { 'Compaq-Peer' }
            '111' { 'IPX-in-IP' }
            '112' { 'VRRP' }
            '113' { 'PGM' }
            '115' { 'L2TP' }
            '116' { 'DDX' }
            '117' { 'IATP' }
            '118' { 'STP' }
            '119' { 'SRP' }
            '120' { 'UTI' }
            '121' { 'SMP' }
            '122' { 'SM' }
            '123' { 'PTP' }
            '124' { 'ISIS' }
            '125' { 'FIRE' }
            '126' { 'CRTP' }
            '127' { 'CRUDP' }
            '128' { 'SSCOPMCE' }
            '129' { 'IPLT' }
            '130' { 'SPS' }
            '131' { 'PIPE' }
            '132' { 'SCTP' }
            '133' { 'FC' }
            '134' { 'RSVP-E2E-IGNORE' }
            '135' { 'Mobility' }
            '136' { 'UDPLite' }
            '137' { 'MPLS-in-IP' }
            '138' { 'manet' }
            '139' { 'HIP' }
            '140' { 'Shim6' }
            '141' { 'WESP' }
            '142' { 'ROHC' }
            '143' { 'Ethernet' }
            '144' { 'AGGFRAG' }
            '145' { 'NS' }
          }
          if ($Label) { "$($_.protocol) ($Label)" } else { $_.protocol }
        }},
        @{label='icmp_type';expression={$_.icmp.icmp_type}},
        @{label='icmp_code';expression={$_.icmp.icmp_code}},
        @{label='local_address';expression={
          if (($_.local_address | Measure-Object).Count -eq 1 -and $_.local_address[0].address -eq '*') {
            $_.local_address[0].address
          } else {
            $_.local_address
          }
        }},
        @{label='remote_address';expression={
          if (($_.remote_address | Measure-Object).Count -eq 1 -and $_.remote_address[0].address -eq '*') {
            $_.remote_address[0].address
          } else {
            $_.remote_address
          }
        }},
        @{label='local_port';expression={
          if (($_.local_port | Measure-Object).Count -eq 1 -and $_.local_port[0].end -eq 0) {
            $_.local_port[0].start
          } else {
            $_.local_port
          }
        }},
        @{label='remote_port';expression={
          if (($_.remote_port | Measure-Object).Count -eq 1 -and $_.remote_port[0].end -eq 0) {
            $_.remote_port[0].start
          } else {
            $_.remote_port
          }
        }},
        @{label='network_location';expression={
          ($_.fields | Where-Object { $_.name -eq 'network_location' }).values -join ','
        }},
        @{label='image_name';expression={
          ($_.fields | Where-Object { $_.name -eq 'image_name' }).value
        }},
        @{label='service_name';expression={
          ($_.fields | Where-Object { $_.name -eq 'service_name' }).value
        }},
        fqdn_enabled,fqdn,
        @{label='monitor_count';expression={$_.monitor.count}},
        @{label='monitor_period_ms';expression={$_.monitor.period_ms}} | Export-Csv $RulePath -NoTypeInformation
    }
  } catch {
    throw $_
  } finally {
    if ((Test-FalconToken).Token -eq $true) { Revoke-FalconToken }
  }
}
end {
  if (Test-Path (Join-Path (Get-Location).Path 'firewall*.csv')) {
    Get-ChildItem -Name firewall*.csv | Select-Object FullName,Length,LastWriteTime
  }
}