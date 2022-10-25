@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.3'
    CompatiblePSEditions = @('Desktop','Core')
    GUID                 = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'
    Author               = 'Brendan Kremian'
    CompanyName          = 'CrowdStrike'
    Copyright            = '(c) CrowdStrike. All rights reserved.'
    Description          = 'PowerShell for the CrowdStrike Falcon OAuth2 APIs'
    HelpInfoURI          = 'https://github.com/CrowdStrike/psfalcon/wiki'
    PowerShellVersion    = '5.1'
    RequiredAssemblies   = @('System.Net.Http')
    ScriptsToProcess     = @('Class/Class.ps1')
    FunctionsToExport    = @(
      # alerts
      'Get-FalconAlert',
      'Invoke-FalconAlertAction',

      # cloud-connect-aws
      'Confirm-FalconDiscoverAwsAccess',
      'Edit-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsSetting',
      'New-FalconDiscoverAwsAccount',
      'Remove-FalconDiscoverAwsAccount',
      'Update-FalconDiscoverAwsSetting',

      # cloud-connect-azure
      'Get-FalconDiscoverAzureAccount',
      'Get-FalconDiscoverAzureCertificate',
      'New-FalconDiscoverAzureAccount',
      'Receive-FalconDiscoverAzureScript',
      'Update-FalconDiscoverAzureAccount',

      # cloud-connect-cspm-aws
      'Edit-FalconHorizonAwsAccount',
      'Get-FalconHorizonAwsAccount',
      'Get-FalconHorizonAwsLink',
      'New-FalconHorizonAwsAccount',
      'Receive-FalconHorizonAwsScript',
      'Remove-FalconHorizonAwsAccount',

      # cloud-connect-cspm-azure
      'Edit-FalconHorizonAzureAccount',
      'Get-FalconHorizonAzureAccount',
      'Get-FalconHorizonAzureCertificate',
      'New-FalconHorizonAzureAccount',
      'Receive-FalconHorizonAzureScript',
      'Remove-FalconHorizonAzureAccount',

      # cloud-connect-gcp
      'Get-FalconDiscoverGcpAccount',
      'New-FalconDiscoverGcpAccount',
      'Receive-FalconDiscoverGcpScript',

      # container-security
      'Get-FalconContainerAssessment',
      'Get-FalconContainerSensor',
      'Remove-FalconRegistryCredential',
      'Request-FalconRegistryCredential',
      'Remove-FalconContainerImage',
      'Show-FalconRegistryCredential',

      # detects
      'Edit-FalconDetection',
      'Get-FalconDetection',
      'Get-FalconHorizonIoa',
      'Get-FalconHorizonIom',

      # devices
      'Add-FalconGroupingTag',
      'Edit-FalconHostGroup',
      'Get-FalconHost',
      'Get-FalconHostGroup',
      'Get-FalconHostGroupMember',
      'Invoke-FalconHostAction',
      'Invoke-FalconHostGroupAction',
      'New-FalconHostGroup',
      'Remove-FalconGroupingTag',
      'Remove-FalconHostGroup',

      # discover
      'Get-FalconAsset',

      # falcon-complete-dashboards
      'Get-FalconCompleteAllowlist',
      'Get-FalconCompleteBlocklist',
      'Get-FalconCompleteCollection',
      'Get-FalconCompleteDetection',
      'Get-FalconCompleteEscalation',
      'Get-FalconCompleteIncident',
      'Get-FalconCompleteRemediation',

      # falconx
      'Get-FalconReport',
      'Get-FalconSubmission',
      'Get-FalconSubmissionQuota',
      'New-FalconSubmission',
      'Receive-FalconArtifact',
      'Remove-FalconReport',

      # filevantage
      'Get-FalconFimChange',

      # fwmgr
      'Edit-FalconFirewallGroup',
      'Edit-FalconFirewallSetting',
      'Get-FalconFirewallEvent',
      'Get-FalconFirewallField',
      'Get-FalconFirewallGroup',
      'Get-FalconFirewallPlatform',
      'Get-FalconFirewallRule',
      'Get-FalconFirewallSetting',
      'New-FalconFirewallGroup',
      'Remove-FalconFirewallGroup',

      # identity-protection
      'Invoke-FalconIdentityGraph',

      # incidents
      'Get-FalconBehavior',
      'Get-FalconIncident',
      'Get-FalconScore',
      'Invoke-FalconIncidentAction',

      # indicators
      'Get-FalconIocHost',
      'Get-FalconIocProcess',

      # intel
      'Get-FalconActor',
      'Get-FalconIndicator',
      'Get-FalconIntel',
      'Get-FalconRule',
      'Receive-FalconIntel',
      'Receive-FalconRule',

      # installation-tokens
      'Edit-FalconInstallToken',
      'Get-FalconInstallToken',
      'Get-FalconInstallTokenEvent',
      'Get-FalconInstallTokenSetting',
      'New-FalconInstallToken',
      'Remove-FalconInstallToken',

      # ioa
      'Get-FalconHorizonIoaEvent',
      'Get-FalconHorizonIoaUser',

      # ioarules
      'Edit-FalconIoaGroup',
      'Edit-FalconIoaRule',
      'Get-FalconIoaGroup',
      'Get-FalconIoaPlatform',
      'Get-FalconIoaRule',
      'Get-FalconIoaSeverity',
      'Get-FalconIoaType',
      'New-FalconIoaGroup',
      'New-FalconIoaRule',
      'Remove-FalconIoaGroup',
      'Remove-FalconIoaRule',
      'Test-FalconIoaRule',

      # iocs
      'Edit-FalconIoc',
      'Get-FalconIoc',
      'New-FalconIoc',
      'Remove-FalconIoc',

      # kubernetes-protection
      'Edit-FalconContainerAwsAccount',
      'Get-FalconContainerAwsAccount',
      'Get-FalconContainerCloud',
      'Get-FalconContainerCluster',
      'Invoke-FalconContainerScan',
      'New-FalconContainerAwsAccount',
      'New-FalconContainerKey',
      'Receive-FalconContainerYaml',
      'Remove-FalconContainerAwsAccount',

      # malquery
      'Get-FalconMalQuery',
      'Get-FalconMalQueryQuota',
      'Get-FalconMalQuerySample',
      'Group-FalconMalQuerySample',
      'Invoke-FalconMalQuery',
      'Receive-FalconMalQuerySample',
      'Search-FalconMalQueryHash',

      # message-center
      'Add-FalconCompleteActivity',
      'Edit-FalconCompleteCase',
      'New-FalconCompleteCase',
      'Get-FalconCompleteActivity',
      'Get-FalconCompleteCase',
      'Receive-FalconCompleteAttachment',
      'Send-FalconCompleteAttachment',

      # mobile-enrollment
      'Invoke-FalconMobileAction',

      # mssp
      'Add-FalconCidGroupMember',
      'Add-FalconGroupRole',
      'Add-FalconUserGroupMember',
      'Edit-FalconCidGroup',
      'Edit-FalconUserGroup',
      'Get-FalconCidGroup',
      'Get-FalconCidGroupMember',
      'Get-FalconGroupRole',
      'Get-FalconMemberCid',
      'Get-FalconUserGroup',
      'Get-FalconUserGroupMember',
      'New-FalconCidGroup',
      'New-FalconUserGroup',
      'Remove-FalconCidGroup',
      'Remove-FalconCidGroupMember',
      'Remove-FalconGroupRole',
      'Remove-FalconUserGroup',
      'Remove-FalconUserGroupMember',

      # oauth2
      'Request-FalconToken',
      'Revoke-FalconToken',
      'Test-FalconToken',

      # overwatch-dashboards
      'Get-FalconOverWatchEvent',
      'Get-FalconOverWatchDetection',
      'Get-FalconOverWatchIncident',

      # policy-device-control
      'Edit-FalconDeviceControlPolicy',
      'Get-FalconDeviceControlPolicy',
      'Get-FalconDeviceControlPolicyMember',
      'Invoke-FalconDeviceControlPolicyAction',
      'New-FalconDeviceControlPolicy',
      'Remove-FalconDeviceControlPolicy',
      'Set-FalconDeviceControlPrecedence',

      # policy-firewall-management
      'Edit-FalconFirewallPolicy',
      'Get-FalconFirewallPolicy',
      'Get-FalconFirewallPolicyMember',
      'Invoke-FalconFirewallPolicyAction',
      'New-FalconFirewallPolicy',
      'Remove-FalconFirewallPolicy',
      'Set-FalconFirewallPrecedence',

      # policy-ioa-exclusions
      'ConvertTo-FalconIoaExclusion',
      'Edit-FalconIoaExclusion',
      'Get-FalconIoaExclusion',
      'New-FalconIoaExclusion',
      'Remove-FalconIoaExclusion',

      # policy-ml-exclusions
      'ConvertTo-FalconMlExclusion',
      'Edit-FalconMlExclusion',
      'Get-FalconMlExclusion',
      'New-FalconMlExclusion',
      'Remove-FalconMlExclusion',

      # policy-prevention
      'Edit-FalconPreventionPolicy',
      'Get-FalconPreventionPolicy',
      'Get-FalconPreventionPolicyMember',
      'Invoke-FalconPreventionPolicyAction',
      'New-FalconPreventionPolicy',
      'Remove-FalconPreventionPolicy',
      'Set-FalconPreventionPrecedence',

      # policy-response
      'Edit-FalconResponsePolicy',
      'Get-FalconResponsePolicy',
      'Get-FalconResponsePolicyMember'
      'Invoke-FalconResponsePolicyAction',
      'New-FalconResponsePolicy',
      'Remove-FalconResponsePolicy',
      'Set-FalconResponsePrecedence',

      # policy-sensor-update
      'Edit-FalconSensorUpdatePolicy',
      'Get-FalconBuild',
      'Get-FalconKernel',
      'Get-FalconSensorUpdatePolicy',
      'Get-FalconSensorUpdatePolicyMember',
      'Get-FalconUninstallToken',
      'Invoke-FalconSensorUpdatePolicyAction',
      'New-FalconSensorUpdatePolicy',
      'Remove-FalconSensorUpdatePolicy',
      'Set-FalconSensorUpdatePrecedence',

      # policy-sv-exclusions
      'Edit-FalconSvExclusion',
      'Get-FalconSvExclusion',
      'New-FalconSvExclusion',
      'Remove-FalconSvExclusion',

      # psf-config
      'Export-FalconConfig',
      'Import-FalconConfig',

      # psf-devices
      'Find-FalconDuplicate',
      'Find-FalconHostname',

      # psf-humio
      'Register-FalconEventCollector',
      'Send-FalconEvent',
      'Show-FalconEventCollector',
      'Unregister-FalconEventCollector',

      # psf-output
      'Export-FalconReport',
      'Send-FalconWebhook',
      'Show-FalconMap',
      'Show-FalconModule',

      # psf-policies
      'Compare-FalconPreventionPhase',
      'Copy-FalconDeviceControlPolicy',
      'Copy-FalconFirewallPolicy',
      'Copy-FalconPreventionPolicy',
      'Copy-FalconResponsePolicy',
      'Copy-FalconSensorUpdatePolicy',

      # psf-sensors
      'Add-FalconSensorTag',
      'Get-FalconSensorTag',
      'Remove-FalconSensorTag',
      'Uninstall-FalconSensor',

      # psf-real-time-response
      'Get-FalconQueue',
      'Invoke-FalconDeploy',
      'Invoke-FalconRtr',

      # quarantine
      'Get-FalconQuarantine',
      'Invoke-FalconQuarantineAction',
      'Test-FalconQuarantineAction',

      # real-time-response
      'Confirm-FalconAdminCommand',
      'Confirm-FalconCommand',
      'Confirm-FalconGetFile',
      'Confirm-FalconResponderCommand',
      'Edit-FalconScript',
      'Get-FalconPutFile',
      'Get-FalconScript',
      'Get-FalconSession',
      'Invoke-FalconAdminCommand',
      'Invoke-FalconBatchGet',
      'Invoke-FalconCommand',
      'Invoke-FalconResponderCommand',
      'Receive-FalconGetFile',
      'Remove-FalconCommand',
      'Remove-FalconGetFile',
      'Remove-FalconPutFile',
      'Remove-FalconScript',
      'Remove-FalconSession',
      'Send-FalconPutFile',
      'Send-FalconScript',
      'Start-FalconSession',
      'Update-FalconSession',

      # recon
      'Edit-FalconReconAction',
      'Edit-FalconReconNotification',
      'Edit-FalconReconRule',
      'Get-FalconReconAction',
      'Get-FalconReconNotification',
      'Get-FalconReconRule',
      'Get-FalconReconRulePreview',
      'New-FalconReconAction',
      'New-FalconReconRule',
      'Remove-FalconReconAction',
      'Remove-FalconReconRule',
      'Remove-FalconReconNotification',

      # reports
      'Get-FalconScheduledReport',
      'Invoke-FalconScheduledReport',
      'Receive-FalconScheduledReport',
      'Redo-FalconScheduledReport',

      # samples
      'Get-FalconSample',
      'Send-FalconSample',
      'Receive-FalconSample',
      'Remove-FalconSample',

      # scanner
      'Get-FalconQuickScan',
      'Get-FalconQuickScanQuota',
      'New-FalconQuickScan',

      # sensors
      'Get-FalconCcid',
      'Get-FalconInstaller',
      'Get-FalconStream',
      'Receive-FalconInstaller',
      'Update-FalconStream',

      # settings
      'Edit-FalconHorizonPolicy',
      'Edit-FalconHorizonSchedule',
      'Get-FalconHorizonPolicy',
      'Get-FalconHorizonSchedule',

      # spotlight
      'Get-FalconRemediation',
      'Get-FalconVulnerability',
      'Get-FalconVulnerabilityLogic',

      # ti
      'Get-FalconTailoredEvent',
      'Get-FalconTailoredRule',

      # user-management
      'Add-FalconRole',
      'Edit-FalconUser',
      'Get-FalconRole',
      'Get-FalconUser',
      'Invoke-FalconUserAction',
      'New-FalconUser',
      'Remove-FalconRole',
      'Remove-FalconUser',

      # zero-trust-assessment
      'Get-FalconZta'
    )
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('CrowdStrike','Falcon','OAuth2','REST','API','PSEdition_Desktop','PSEdition_Core',
                'Windows','Linux','MacOS')
            LicenseUri   = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/LICENSE'
            ProjectUri   = 'https://github.com/crowdstrike/psfalcon'
            IconUri      = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/icon.png'
            ReleaseNotes = "@
New Commands

* psf-policies
  'Compare-FalconPreventionPhase'

* ti
  'Get-FalconTailoredEvent'
  'Get-FalconTailoredRule'

General Changes

* Created 'Confirm-Property' private function to filter [hashtable] and [PSCustomObject] into pre-defined
  properties containing values.

* Updated comment-based help to link directly to specific wiki pages for each command. Using 'Get-Help <command>
  -Online' will launch the appropriate wiki page. These pages will be updated with current examples present within
  existing wiki pages, and those pages will be re-organized.

* Modified 'Get-ParamSet' private function to look for 'ids' and 'samples' as potential body values to break into
  groups of 'Max' values, instead of only 'ids'.

* Updated Falcon X references to Falcon Intelligence due to product name change.

Command Changes

* Updated 'Invoke-FalconIdentityGraph' to no longer modify the GraphQL statement when attempting to use '-All' for
  pagination. Renamed 'Query' parameter to 'String' and made it work for both query and mutation statements but
  kept 'Query' as an alias. Now, when your statement includes a 'Cursor' variable definition and the required
  'pageInfo { hasNextPage endCursor }' properties, '-All' will automatically paginate results. If either of those
  requirements are missing, a warning message will be displayed and pagination will not occur.

* Modified 'Get-FalconUser' to remove deprecated API when using 'Username' parameter. 'Username' now submits
  filtered searches for provided 'uid' values to the appropriate /user-management/ API.

* Added 'Max' of 1,000 sha256 values for 'New-FalconQuickScan'.

* Added 'sha256' as a PipelineByPropertyName value for 'New-FalconQuickScan' to support pipeline input from
  'Send-FalconSample'.

* Added pattern validation to 'Remove-FalconUser' for the 'Id' parameter.

* Modified 'Status' parameter for 'Edit-FalconDetection' to support ValueFromPipelineByPropertyName and changed
  parameter to position 3.

Resolved Issues

* Issue #241: Updated 'Confirm-Parameter' to eliminate 'Cannot validate argument on parameter 'Array'. Key cannot
  be null. (Parameter 'key')' errors generated when using 'Import-FalconConfig'.

* Issue #242: Modified 'Edit-FalconDetection' to check whether a 'status' value is present with a 'comment' value
  during command execution rather than during parameter validation. This will prevent errors from occurring when
  parameters are specified in an unexpected order.

* Issue #246: Created 'Confirm-Property' function to properly filter 'Rule' content for both [hashtable] and
  [PSCustomObject] rules. This will eliminate errors caused by [hashtable] objects being improperly filtered
  in PowerShell 5.1.

  * Issue #247: Updated 'Write-Warning' to use a PSCmdlet method in order to properly support 'WarningVariable'.
@"
        }
    }
}