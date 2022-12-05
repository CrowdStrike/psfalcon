@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.4'
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
      'Get-FalconAlert'
      'Invoke-FalconAlertAction'

      # cloud-connect-aws
      'Confirm-FalconDiscoverAwsAccess'
      'Edit-FalconDiscoverAwsAccount'
      'Get-FalconDiscoverAwsAccount'
      'Get-FalconDiscoverAwsLink'
      'Get-FalconDiscoverAwsSetting'
      'New-FalconDiscoverAwsAccount'
      'Receive-FalconDiscoverAwsScript'
      'Remove-FalconDiscoverAwsAccount'
      'Update-FalconDiscoverAwsSetting'

      # cloud-connect-azure
      'Get-FalconDiscoverAzureAccount'
      'Get-FalconDiscoverAzureCertificate'
      'New-FalconDiscoverAzureAccount'
      'Receive-FalconDiscoverAzureScript'
      'Update-FalconDiscoverAzureAccount'

      # cloud-connect-cspm-aws
      'Edit-FalconHorizonAwsAccount'
      'Get-FalconHorizonAwsAccount'
      'Get-FalconHorizonAwsLink'
      'New-FalconHorizonAwsAccount'
      'Receive-FalconHorizonAwsScript'
      'Remove-FalconHorizonAwsAccount'

      # cloud-connect-cspm-azure
      'Edit-FalconHorizonAzureAccount'
      'Get-FalconHorizonAzureAccount'
      'Get-FalconHorizonAzureCertificate'
      'New-FalconHorizonAzureAccount'
      'Receive-FalconHorizonAzureScript'
      'Remove-FalconHorizonAzureAccount'

      # cloud-connect-gcp
      'Get-FalconDiscoverGcpAccount'
      'New-FalconDiscoverGcpAccount'
      'Receive-FalconDiscoverGcpScript'

      # container-security
      'Get-FalconContainerAssessment'
      'Get-FalconContainerSensor'
      'Remove-FalconRegistryCredential'
      'Request-FalconRegistryCredential'
      'Remove-FalconContainerImage'
      'Show-FalconRegistryCredential'

      # detects
      'Edit-FalconDetection'
      'Get-FalconDetection'
      'Get-FalconHorizonIoa'
      'Get-FalconHorizonIom'

      # devices
      'Add-FalconGroupingTag'
      'Edit-FalconHostGroup'
      'Get-FalconHost'
      'Get-FalconHostGroup'
      'Get-FalconHostGroupMember'
      'Invoke-FalconHostAction'
      'Invoke-FalconHostGroupAction'
      'New-FalconHostGroup'
      'Remove-FalconGroupingTag'
      'Remove-FalconHostGroup'

      # discover
      'Get-FalconAsset'

      # enrollments
      'Invoke-FalconMobileAction'

      # falcon-complete-dashboards
      'Get-FalconCompleteAllowlist'
      'Get-FalconCompleteBlocklist'
      'Get-FalconCompleteCollection'
      'Get-FalconCompleteDetection'
      'Get-FalconCompleteEscalation'
      'Get-FalconCompleteIncident'
      'Get-FalconCompleteRemediation'

      # falconx
      'Get-FalconReport'
      'Get-FalconSubmission'
      'Get-FalconSubmissionQuota'
      'New-FalconSubmission'
      'Receive-FalconArtifact'
      'Remove-FalconReport'

      # filevantage
      'Get-FalconFimChange'

      # fwmgr
      'Edit-FalconFirewallGroup'
      'Edit-FalconFirewallSetting'
      'Get-FalconFirewallEvent'
      'Get-FalconFirewallField'
      'Get-FalconFirewallGroup'
      'Get-FalconFirewallPlatform'
      'Get-FalconFirewallRule'
      'Get-FalconFirewallSetting'
      'New-FalconFirewallGroup'
      'Remove-FalconFirewallGroup'
      'Test-FalconFirewallPath'

      # identity-protection
      'Invoke-FalconIdentityGraph'

      # image-assessment
      'Get-FalconContainerVulnerability'

      # incidents
      'Get-FalconBehavior'
      'Get-FalconIncident'
      'Get-FalconScore'
      'Invoke-FalconIncidentAction'

      # indicators
      'Get-FalconIocHost'
      'Get-FalconIocProcess'

      # intel
      'Get-FalconActor'
      'Get-FalconIndicator'
      'Get-FalconIntel'
      'Get-FalconRule'
      'Receive-FalconIntel'
      'Receive-FalconRule'

      # installation-tokens
      'Edit-FalconInstallToken'
      'Edit-FalconInstallTokenSetting'
      'Get-FalconInstallToken'
      'Get-FalconInstallTokenEvent'
      'Get-FalconInstallTokenSetting'
      'New-FalconInstallToken'
      'Remove-FalconInstallToken'

      # ioa
      'Get-FalconHorizonIoaEvent'
      'Get-FalconHorizonIoaUser'

      # ioarules
      'Edit-FalconIoaGroup'
      'Edit-FalconIoaRule'
      'Get-FalconIoaGroup'
      'Get-FalconIoaPlatform'
      'Get-FalconIoaRule'
      'Get-FalconIoaSeverity'
      'Get-FalconIoaType'
      'New-FalconIoaGroup'
      'New-FalconIoaRule'
      'Remove-FalconIoaGroup'
      'Remove-FalconIoaRule'
      'Test-FalconIoaRule'

      # iocs
      'Edit-FalconIoc'
      'Get-FalconIoc'
      'Get-FalconIocAction'
      'Get-FalconIocPlatform'
      'Get-FalconIocSeverity'
      'Get-FalconIocType'
      'New-FalconIoc'
      'Remove-FalconIoc'

      # kubernetes-protection
      'Edit-FalconContainerAwsAccount'
      'Get-FalconContainerAwsAccount'
      'Get-FalconContainerCloud'
      'Get-FalconContainerCluster'
      'Invoke-FalconContainerScan'
      'New-FalconContainerAwsAccount'
      'New-FalconContainerKey'
      'Receive-FalconContainerYaml'
      'Remove-FalconContainerAwsAccount'

      # malquery
      'Get-FalconMalQuery'
      'Get-FalconMalQueryQuota'
      'Get-FalconMalQuerySample'
      'Group-FalconMalQuerySample'
      'Invoke-FalconMalQuery'
      'Receive-FalconMalQuerySample'
      'Search-FalconMalQueryHash'

      # message-center
      'Add-FalconCompleteActivity'
      'Edit-FalconCompleteCase'
      'New-FalconCompleteCase'
      'Get-FalconCompleteActivity'
      'Get-FalconCompleteCase'
      'Receive-FalconCompleteAttachment'
      'Send-FalconCompleteAttachment'

      # mssp
      'Add-FalconCidGroupMember'
      'Add-FalconGroupRole'
      'Add-FalconUserGroupMember'
      'Edit-FalconCidGroup'
      'Edit-FalconUserGroup'
      'Get-FalconCidGroup'
      'Get-FalconCidGroupMember'
      'Get-FalconGroupRole'
      'Get-FalconMemberCid'
      'Get-FalconUserGroup'
      'Get-FalconUserGroupMember'
      'New-FalconCidGroup'
      'New-FalconUserGroup'
      'Remove-FalconCidGroup'
      'Remove-FalconCidGroupMember'
      'Remove-FalconGroupRole'
      'Remove-FalconUserGroup'
      'Remove-FalconUserGroupMember'

      # oauth2
      'Request-FalconToken'
      'Revoke-FalconToken'
      'Test-FalconToken'

      # ods
      'Get-FalconScan'
      'Get-FalconScanFile'
      'Get-FalconScanHost'
      'Get-FalconScheduledScan'
      'New-FalconScheduledScan'
      'Remove-FalconScheduledScan'
      'Start-FalconScan'
      'Stop-FalconScan'

      # overwatch-dashboards
      'Get-FalconOverWatchEvent'
      'Get-FalconOverWatchDetection'
      'Get-FalconOverWatchIncident'

      # policy-device-control
      'Edit-FalconDeviceControlPolicy'
      'Get-FalconDeviceControlPolicy'
      'Get-FalconDeviceControlPolicyMember'
      'Invoke-FalconDeviceControlPolicyAction'
      'New-FalconDeviceControlPolicy'
      'Remove-FalconDeviceControlPolicy'
      'Set-FalconDeviceControlPrecedence'

      # policy-firewall-management
      'Edit-FalconFirewallPolicy'
      'Get-FalconFirewallPolicy'
      'Get-FalconFirewallPolicyMember'
      'Invoke-FalconFirewallPolicyAction'
      'New-FalconFirewallPolicy'
      'Remove-FalconFirewallPolicy'
      'Set-FalconFirewallPrecedence'

      # policy-ioa-exclusions
      'ConvertTo-FalconIoaExclusion'
      'Edit-FalconIoaExclusion'
      'Get-FalconIoaExclusion'
      'New-FalconIoaExclusion'
      'Remove-FalconIoaExclusion'

      # policy-ml-exclusions
      'ConvertTo-FalconMlExclusion'
      'Edit-FalconMlExclusion'
      'Get-FalconMlExclusion'
      'New-FalconMlExclusion'
      'Remove-FalconMlExclusion'

      # policy-prevention
      'Edit-FalconPreventionPolicy'
      'Get-FalconPreventionPolicy'
      'Get-FalconPreventionPolicyMember'
      'Invoke-FalconPreventionPolicyAction'
      'New-FalconPreventionPolicy'
      'Remove-FalconPreventionPolicy'
      'Set-FalconPreventionPrecedence'

      # policy-response
      'Edit-FalconResponsePolicy'
      'Get-FalconResponsePolicy'
      'Get-FalconResponsePolicyMember'
      'Invoke-FalconResponsePolicyAction'
      'New-FalconResponsePolicy'
      'Remove-FalconResponsePolicy'
      'Set-FalconResponsePrecedence'

      # policy-sensor-update
      'Edit-FalconSensorUpdatePolicy'
      'Get-FalconBuild'
      'Get-FalconKernel'
      'Get-FalconSensorUpdatePolicy'
      'Get-FalconSensorUpdatePolicyMember'
      'Get-FalconUninstallToken'
      'Invoke-FalconSensorUpdatePolicyAction'
      'New-FalconSensorUpdatePolicy'
      'Remove-FalconSensorUpdatePolicy'
      'Set-FalconSensorUpdatePrecedence'

      # policy-sv-exclusions
      'Edit-FalconSvExclusion'
      'Get-FalconSvExclusion'
      'New-FalconSvExclusion'
      'Remove-FalconSvExclusion'

      # psf-config
      'Export-FalconConfig'
      'Import-FalconConfig'

      # psf-devices
      'Find-FalconDuplicate'
      'Find-FalconHostname'

      # psf-humio
      'Register-FalconEventCollector'
      'Send-FalconEvent'
      'Show-FalconEventCollector'
      'Unregister-FalconEventCollector'

      # psf-output
      'Export-FalconReport'
      'Send-FalconWebhook'
      'Show-FalconMap'
      'Show-FalconModule'

      # psf-policies
      'Compare-FalconPreventionPhase'
      'Copy-FalconDeviceControlPolicy'
      'Copy-FalconFirewallPolicy'
      'Copy-FalconPreventionPolicy'
      'Copy-FalconResponsePolicy'
      'Copy-FalconSensorUpdatePolicy'

      # psf-sensors
      'Add-FalconSensorTag'
      'Get-FalconSensorTag'
      'Remove-FalconSensorTag'
      'Uninstall-FalconSensor'

      # psf-real-time-response
      'Get-FalconQueue'
      'Invoke-FalconDeploy'
      'Invoke-FalconRtr'

      # quarantine
      'Get-FalconQuarantine'
      'Invoke-FalconQuarantineAction'
      'Test-FalconQuarantineAction'

      # real-time-response
      'Confirm-FalconAdminCommand'
      'Confirm-FalconCommand'
      'Confirm-FalconGetFile'
      'Confirm-FalconResponderCommand'
      'Edit-FalconScript'
      'Get-FalconPutFile'
      'Get-FalconScript'
      'Get-FalconSession'
      'Invoke-FalconAdminCommand'
      'Invoke-FalconBatchGet'
      'Invoke-FalconCommand'
      'Invoke-FalconResponderCommand'
      'Receive-FalconGetFile'
      'Remove-FalconCommand'
      'Remove-FalconGetFile'
      'Remove-FalconPutFile'
      'Remove-FalconScript'
      'Remove-FalconSession'
      'Send-FalconPutFile'
      'Send-FalconScript'
      'Start-FalconSession'
      'Update-FalconSession'

      # recon
      'Edit-FalconReconAction'
      'Edit-FalconReconNotification'
      'Edit-FalconReconRule'
      'Get-FalconReconAction'
      'Get-FalconReconNotification'
      'Get-FalconReconRule'
      'Get-FalconReconRulePreview'
      'New-FalconReconAction'
      'New-FalconReconRule'
      'Remove-FalconReconAction'
      'Remove-FalconReconRule'
      'Remove-FalconReconNotification'

      # reports
      'Get-FalconScheduledReport'
      'Invoke-FalconScheduledReport'
      'Receive-FalconScheduledReport'
      'Redo-FalconScheduledReport'

      # samples
      'Get-FalconSample'
      'Send-FalconSample'
      'Receive-FalconSample'
      'Remove-FalconSample'

      # scanner
      'Get-FalconQuickScan'
      'Get-FalconQuickScanQuota'
      'New-FalconQuickScan'

      # sensors
      'Get-FalconCcid'
      'Get-FalconInstaller'
      'Get-FalconStream'
      'Receive-FalconInstaller'
      'Update-FalconStream'

      # settings
      'Edit-FalconHorizonPolicy'
      'Edit-FalconHorizonSchedule'
      'Get-FalconHorizonPolicy'
      'Get-FalconHorizonSchedule'

      # settings-discover
      'Get-FalconDiscoverAwsScript'

      # spotlight
      'Get-FalconRemediation'
      'Get-FalconVulnerability'
      'Get-FalconVulnerabilityLogic'

      # ti
      'Get-FalconTailoredEvent'
      'Get-FalconTailoredRule'

      # user-management
      'Add-FalconRole'
      'Edit-FalconUser'
      'Get-FalconRole'
      'Get-FalconUser'
      'Invoke-FalconUserAction'
      'New-FalconUser'
      'Remove-FalconRole'
      'Remove-FalconUser'

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

# New Commands
  ### cloud-connect-aws
  * Get-FalconDiscoverAwsLink
  * Receive-FalconDiscoverAwsScript
  ### fwmgr
  * Test-FalconFirewallPath
  ### installation-tokens
  * Edit-FalconInstallTokenSetting
  ### image-assessment
  * Get-FalconContainerVulnerability
  ### iocs
  * Get-FalconIocAction
  * Get-FalconIocPlatform
  * Get-FalconIocSeverity
  * Get-FalconIocType
  ### ods
  * Get-FalconScan
  * Get-FalconScanFile
  * Get-FalconScanHost
  * Get-FalconScheduledScan
  * New-FalconScheduledScan
  * Remove-FalconScheduledScan
  * Start-FalconScan
  * Stop-FalconScan
  ### settings-discover
  * Get-FalconDiscoverAwsScript

# Issues Resolved
  * Issue #255: Added missing parameters and maximum limit of 100 'ids' per 'detailed' request.
  * Issue #256: Removed type definition when creating build tag variables. Added filter to ensure that LinuxArm64
    builds were only being checked when they were using tagged versions.

# General Changes
  * Renamed 'mobile-enrollment.ps1' to 'enrollments.ps1' to match URL prefix.
  * Created 'Test-StringPattern' private function for validating values passed to parameters that accept [object[]]
    values which are ultimately filtered down to [string]. This function is used to output error messages when the
    proper 'id' values are not found in objects submitted from the pipeline.

# Command Changes
## Add-FalconRole
  * Removed deprecated endpoint '/user-roles/entities/user-roles/v1:post'. This command now uses the
    '/user-management/entities/user-role-actions/v1:post' endpoint exclusively (using 'action: grant').
  * Changed parameter positions and removed pipeline support for 'Id'.
  * 'Cid' is now a required parameter due to the endpoint change. 'Cid' is included in a 'Get-FalconUser
    -Detailed' result.
## Compare-FalconPreventionPhase
  * Updated reference Json files.
## Edit-FalconCompleteCase
  * Updated 'DetectionId' and 'IncidentId' to submit as hashtables with 'id' property, rather than an array of
    string values.
## Edit-FalconFirewallGroup
  * Added 'Validate' parameter to utilize new '/fwmgr/entities/rule-groups/validation/v1:patch' endpoint.
## Edit-FalconFirewallSetting
  * Updated to use new '/fwmgr/entities/policies/v2:put' endpoint.
## Edit-FalconHorizonSchedule
  * Added 'NextScanTimestamp' parameter.
## Edit-FalconIoaExclusion
  * Added 'PatternId' and 'PatternName' parameters.
## Edit-FalconIoc
  * Added 'FromParent' parameter.
  * Modified how 'Filename' is submitted to prevent potential errors.
## Edit-FalconReconAction
  * Added 'ContentFormat' and 'TriggerMatchless' parameters.
## Edit-FalconReconRule
  * Added 'BreachMonitoring' and 'SubstringMatching' parameters.
## Find-FalconHostname
  * Added 'Partial' switch to perform non-exact matches, an idea from Reddit user 'Runs_on_empty'.
  * Added 'Include' parameter.
## Get-FalconCidGroup
  * Updated to use new v2 endpoint.
## Get-FalconCidGroupMember
  * Updated to use new v2 endpoint.
## Get-FalconDiscoverAwsAccount
  * Updated to use new v2 endpoint.
  * Because the v2 endpoint no longer includes them, 'Filter' and 'Sort' have been removed from available
    parameters, but 'Migrated', 'OrganizationId' and 'ScanType' have been added.
  * 'Detailed' has been removed because a single call now includes details.
## Get-FalconHorizonIoaEvent
  * Added 'State' parameter.
  * Renamed 'UserIds' parameter to 'UserId' but kept 'UserIds' as an alias.
## Get-FalconHorizonIoaUser
  * Added 'State' parameter.
## Get-FalconHorizonSchedule
  * Changed 'CloudPlatform' to mandatory, as the API no longer returns results without specifying a value.
## Get-FalconIndicator
  * Added 'IncludeRelation' parameter.
## Get-FalconIoc
  * Added 'FromParent' parameter.
## Get-FalconMemberCid
  * Updated to use new v2 endpoint.
## Get-FalconRole
  * Added error message when a user attempts to pipeline a detailed 'Get-FalconUser' result to 'Get-FalconRole'.
  * Added auto-complete for 'Id' using list of roles from authorized CID.
## Get-FalconUser
  * Added 'All' and 'Total' parameters. These were mistakenly missed in the 2.2.3 release.
  * Added maximum of 100 user ids per 'detailed' request.
## Get-FalconUserGroup
  * Updated to use new v2 endpoint.
## Get-FalconUserGroupMember
  * Updated to use new v2 endpoint.
## Invoke-FalconAdminCommand
  * Added 'HostTimeout' parameter.
  * Updated 'Timeout' and 'HostTimeout' accepted ranges from 30-600 to 1-600.
  * Re-ordered positioning of 'Timeout' parameter.
## Invoke-FalconBatchGet
  * Added 'HostTimeout' parameter.
  * Updated 'Timeout' and 'HostTimeout' accepted ranges from 30-600 to 1-600.
  * Re-ordered positioning of 'Timeout' parameter.
## Invoke-FalconCommand
  * Added 'HostTimeout' parameter.
  * Updated 'Timeout' and 'HostTimeout' accepted ranges from 30-600 to 1-600.
## Invoke-FalconResponderCommand
  * Added 'HostTimeout' parameter.
  * Updated 'Timeout' and 'HostTimeout' accepted ranges from 30-600 to 1-600.
## New-FalconCompleteCase
  * Updated 'DetectionId' and 'IncidentId' to submit as hashtables with 'id' property, rather than an array of
    string values.
## New-FalconDiscoverAwsAccount
  * Updated to use new '/cloud-connect-aws/entities/account/v2:post' endpoint. Parameters have changed to match
    new endpoint.
## New-FalconFirewallGroup
  * Added 'Validate' parameter to utilize new '/fwmgr/entities/rule-groups/validation/v1:post' endpoint.
  * Added 'Platform' parameter, with auto-complete using 'Get-FalconFirewallPlatform' for available values.
## New-FalconIoc
  * Modified how 'Filename' is submitted to prevent potential errors.
## New-FalconReconAction
  * Added 'ContentFormat' and 'TriggerMatchless' parameters.
## New-FalconReconRule
  * Added 'BreachMonitoring' and 'SubstringMatching' parameters.
## Remove-FalconDiscoverAwsAccount
  * Updated to use new '/cloud-connect-aws/entities/account/v2:delete' endpoint. Parameters have changed to match
  new endpoint.
## Remove-FalconIoc
  * Added 'FromParent' parameter.
## Remove-FalconRole
  * Removed deprecated endpoint '/user-roles/entities/user-roles/v1:delete'. This command now uses the
    '/user-management/entities/user-role-actions/v1:post' endpoint exclusively (using 'action: revoke').
  * Changed parameter positions and removed pipeline support for 'Id'.
  * 'Cid' is now a required parameter due to the endpoint change. 'Cid' is included in a 'Get-FalconUser
    -Detailed' result.
## Start-FalconSession
  * Added 'HostTimeout' parameter.
  * Added 'Timeout' parameter to 'Start-FalconSession' when working with single-host sessions. 'Timeout' would
    previously force a batch session to be created even if a single host was submitted. Now that 'Timeout' also
    works for single host sessions, 'HostTimeout' or 'ExistingBatchId' must be used to force creation of a batch
    session.
  * Updated 'Timeout' and 'HostTimeout' accepted ranges from 30-600 to 1-600.
@"
        }
    }
}