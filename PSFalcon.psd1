@{
  RootModule = 'PSFalcon.psm1'
  ModuleVersion = '2.2.7'
  CompatiblePSEditions = @('Desktop','Core')
  GUID = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'
  Author = 'Brendan Kremian'
  CompanyName = 'CrowdStrike'
  Copyright = '(c) CrowdStrike. All rights reserved.'
  Description = 'PowerShell for the CrowdStrike Falcon OAuth2 APIs'
  HelpInfoURI = 'https://github.com/CrowdStrike/psfalcon/wiki'
  PowerShellVersion = '5.1'
  RequiredAssemblies = @('System.Net.Http')
  FunctionsToExport = @(
    # alerts
    'Get-FalconAlert'
    'Invoke-FalconAlertAction'

    # archives
    'Expand-FalconSampleArchive'
    'Get-FalconSampleArchive'
    'Get-FalconSampleExtraction'
    'Remove-FalconSampleArchive'
    'Send-FalconSampleArchive'

    # billing-dashboards-usage
    'Get-FalconHostAverage'

    # cloud-connect-cspm-aws
    'Edit-FalconCloudAwsAccount'
    'Get-FalconCloudAwsAccount'
    'Get-FalconCloudAwsLink'
    'New-FalconCloudAwsAccount'
    'Receive-FalconCloudAwsScript'
    'Remove-FalconCloudAwsAccount'

    # cloud-connect-cspm-azure
    'Edit-FalconCloudAzureAccount'
    'Get-FalconCloudAzureAccount'
    'Get-FalconCloudAzureCertificate'
    'Get-FalconCloudAzureGroup'
    'New-FalconCloudAzureAccount'
    'New-FalconCloudAzureGroup'
    'Receive-FalconCloudAzureScript'
    'Remove-FalconCloudAzureAccount'
    'Remove-FalconCloudAzureGroup'

    # cloud-connect-cspm-gcp
    'Edit-FalconCloudGcpAccount'
    'Edit-FalconCloudGcpServiceAccount'
    'Get-FalconCloudGcpAccount'
    'Get-FalconCloudGcpServiceAccount'
    'Invoke-FalconCloudGcpHealthCheck'
    'New-FalconCloudGcpAccount'
    'Receive-FalconCloudGcpScript'
    'Remove-FalconCloudGcpAccount'
    'Test-FalconCloudGcpServiceAccount'

    # configuration-assessment
    'Get-FalconConfigAssessment'
    'Get-FalconConfigAssessmentLogic'
    'Get-FalconConfigAssessmentRule'

    # container-security
    'Edit-FalconContainerPolicy'
    'Edit-FalconContainerPolicyGroup'
    'Edit-FalconContainerRegistry'
    'Get-FalconContainer'
    'Get-FalconContainerAlert'
    'Get-FalconContainerAssessment'
    'Get-FalconContainerDeployment'
    'Get-FalconContainerDetection'
    'Get-FalconContainerCluster'
    'Get-FalconContainerCount'
    'Get-FalconContainerDriftIndicator'
    'Get-FalconContainerImage'
    'Get-FalconContainerIom'
    'Get-FalconContainerNode'
    'Get-FalconContainerPackage'
    'Get-FalconContainerPod'
    'Get-FalconContainerPolicy'
    'Get-FalconContainerPolicyExclusion'
    'Get-FalconContainerPolicyGroup'
    'Get-FalconContainerRegistry'
    'Get-FalconContainerSensor'
    'Get-FalconContainerVulnerability'
    'New-FalconContainerImage'
    'New-FalconContainerPolicy'
    'New-FalconContainerPolicyExclusion'
    'New-FalconContainerPolicyGroup'
    'New-FalconContainerRegistry'
    'Remove-FalconContainerImage'
    'Remove-FalconContainerRegistry'
    'Remove-FalconContainerPolicy'
    'Remove-FalconContainerPolicyGroup'
    'Remove-FalconRegistryCredential'
    'Request-FalconRegistryCredential'
    'Set-FalconContainerPolicyPrecedence'
    'Show-FalconRegistryCredential'

    # delivery-settings
    'Get-FalconChannelControl'
    'Set-FalconChannelControl'

    # detects
    'Edit-FalconDetection'
    'Get-FalconDetection'
    'Get-FalconCloudIoa'
    'Get-FalconCloudIom'

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

    # device-content
    'Get-FalconChannelState'

    # discover
    'Get-FalconAsset'

    # enrollments
    'Invoke-FalconMobileAction'

    # exclusions
    'Edit-FalconCertificateExclusion'
    'Get-FalconCertificate'
    'Get-FalconCertificateExclusion'
    'New-FalconCertificateExclusion'
    'Remove-FalconCertificateExclusion'

    # falcon-complete-dashboards
    'Get-FalconCompleteAlert'
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
    'Receive-FalconMemoryDump'
    'Remove-FalconReport'

    # fem
    'Edit-FalconAsset'

    # fdr
    'Get-FalconReplicatorEvent'
    'Get-FalconReplicatorField'
    'Get-FalconReplicatorSchema'

    # filevantage
    'Add-FalconFileVantageHostGroup'
    'Add-FalconFileVantageRuleGroup'
    'Edit-FalconFileVantageExclusion'
    'Edit-FalconFileVantagePolicy'
    'Edit-FalconFileVantageRule'
    'Edit-FalconFileVantageRuleGroup'
    'Get-FalconFileVantageAction'
    'Get-FalconFileVantageChange'
    'Get-FalconFileVantageContent'
    'Get-FalconFileVantageExclusion'
    'Get-FalconFileVantagePolicy'
    'Get-FalconFileVantageRule'
    'Get-FalconFileVantageRuleGroup'
    'Invoke-FalconFileVantageAction'
    'Invoke-FalconFileVantageWorkflow'
    'New-FalconFileVantageExclusion'
    'New-FalconFileVantagePolicy'
    'New-FalconFileVantageRule'
    'New-FalconFileVantageRuleGroup'
    'Remove-FalconFileVantageExclusion'
    'Remove-FalconFileVantageHostGroup'
    'Remove-FalconFileVantagePolicy'
    'Remove-FalconFileVantageRule'
    'Remove-FalconFileVantageRuleGroup'
    'Set-FalconFileVantagePrecedence'
    'Set-FalconFileVantageRulePrecedence'
    'Set-FalconFileVantageRuleGroupPrecedence'

    # fwmgr
    'Edit-FalconFirewallGroup'
    'Edit-FalconFirewallLocation'
    'Edit-FalconFirewallLocationSetting'
    'Edit-FalconFirewallSetting'
    'Get-FalconFirewallEvent'
    'Get-FalconFirewallField'
    'Get-FalconFirewallGroup'
    'Get-FalconFirewallLocation'
    'Get-FalconFirewallPlatform'
    'Get-FalconFirewallRule'
    'Get-FalconFirewallSetting'
    'New-FalconFirewallGroup'
    'New-FalconFirewallLocation'
    'Remove-FalconFirewallGroup'
    'Remove-FalconFirewallLocation'
    'Set-FalconFirewallLocationPrecedence'
    'Test-FalconFirewallPath'

    # host-migration
    'Get-FalconMigration'
    'Get-FalconMigrationCid'
    'Get-FalconMigrationHost'
    'Invoke-FalconMigrationAction'
    'New-FalconMigration'
    'Start-FalconMigration'
    'Stop-FalconMigration'
    'Rename-FalconMigration'
    'Remove-FalconMigration'

    # identity-protection
    'Invoke-FalconIdentityGraph'
    'Get-FalconIdentityHost'
    'Get-FalconIdentityRule'

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
    'Get-FalconAttck'
    'Get-FalconCve'
    'Get-FalconIndicator'
    'Get-FalconIntel'
    'Get-FalconMalwareFamily'
    'Get-FalconRule'
    'Receive-FalconAttck'
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
    'Edit-FalconContainerAzureAccount'
    'Get-FalconContainerAccount'
    'Get-FalconContainerAwsAccount'
    'Get-FalconContainerAzureAccount'
    'Get-FalconContainerAzureConfig'
    'Get-FalconContainerAzureScript'
    'Get-FalconContainerAzureTenant'
    'Get-FalconContainerCloud'
    'Get-FalconContainerScript'
    'Invoke-FalconContainerScan'
    'New-FalconContainerAwsAccount'
    'New-FalconContainerAzureAccount'
    'New-FalconContainerKey'
    'Receive-FalconContainerYaml'
    'Remove-FalconContainerAwsAccount'
    'Remove-FalconContainerAzureAccount'

    # loggingapi
    'Get-FalconFoundryRepository'
    'Get-FalconFoundrySearch'
    'Get-FalconFoundryView'

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

    # plugins
    'Get-FalconWorkflowIntegration'

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

    # psf-fwmgr
    'ConvertTo-FalconFirewallRule'

    # psf-logscale
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
    'Copy-FalconDeviceControlPolicy'
    'Copy-FalconFirewallPolicy'
    'Copy-FalconPreventionPolicy'
    'Copy-FalconResponsePolicy'
    'Copy-FalconSensorUpdatePolicy'

    # psf-sensors
    'Add-FalconSensorTag'
    'Get-FalconSensorTag'
    'Remove-FalconSensorTag'
    'Set-FalconSensorTag'
    'Uninstall-FalconSensor'

    # psf-real-time-response
    'Get-FalconQueue'
    'Invoke-FalconDeploy'
    'Invoke-FalconRtr'

    # quarantine
    'Get-FalconQuarantine'
    'Invoke-FalconQuarantineAction'
    'Test-FalconQuarantineAction'

    # quickscanpro
    'Get-FalconQuickScan'
    'New-FalconQuickScan'
    'Remove-FalconQuickScan'
    'Remove-FalconQuickScanFile'
    'Send-FalconQuickScanFile'

    # real-time-response
    'Confirm-FalconAdminCommand'
    'Confirm-FalconCommand'
    'Confirm-FalconGetFile'
    'Confirm-FalconResponderCommand'
    'Edit-FalconScript'
    'Get-FalconLibraryScript'
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
    'Get-FalconReconExport'
    'Get-FalconReconNotification'
    'Get-FalconReconRecord'
    'Get-FalconReconRule'
    'Get-FalconReconRulePreview'
    'Invoke-FalconReconExport'
    'New-FalconReconAction'
    'New-FalconReconRule'
    'Receive-FalconReconExport'
    'Remove-FalconReconAction'
    'Remove-FalconReconExport'
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

    # sensors
    'Get-FalconCcid'
    'Get-FalconInstaller'
    'Get-FalconStream'
    'Receive-FalconInstaller'
    'Update-FalconStream'

    # settings
    'Edit-FalconCloudPolicy'
    'Edit-FalconCloudSchedule'
    'Get-FalconCloudPolicy'
    'Get-FalconCloudSchedule'

    # snapshots
    'Get-FalconSnapshot'
    'Get-FalconSnapshotScan'
    'New-FalconSnapshotScan'

    # spotlight
    'Get-FalconRemediation'
    'Get-FalconVulnerability'
    'Get-FalconVulnerabilityLogic'

    # threatgraph
    'Get-FalconThreatGraphEdge'
    'Get-FalconThreatGraphIndicator'
    'Get-FalconThreatGraphVertex'

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

    # workflows
    'Export-FalconWorkflow'
    'Get-FalconWorkflow'
    'Get-FalconWorkflowAction'
    'Get-FalconWorkflowInput'
    'Get-FalconWorkflowTrigger'
    'Import-FalconWorkflow'
    'Invoke-FalconWorkflow'
    'Redo-FalconWorkflow'

    # zero-trust-assessment
    'Get-FalconZta'
  )
  CmdletsToExport = @()
  VariablesToExport = '*'
  AliasesToExport = @('Edit-FalconHorizonAwsAccount','Edit-FalconHorizonAzureAccount','Edit-FalconHorizonPolicy',
    'Edit-FalconHorizonSchedule','Get-FalconFimChange','Get-FalconHorizonAwsAccount','Get-FalconHorizonAwsLink',
    'Get-FalconHorizonAzureAccount','Get-FalconHorizonAzureCertificate','Get-FalconHorizonAzureGroup',
    'Get-FalconHorizonIoa','Get-FalconHorizonIoaEvent','Get-FalconHorizonIoaUser','Get-FalconHorizonIom',
    'Get-FalconHorizonPolicy','Get-FalconHorizonSchedule','New-FalconHorizonAwsAccount',
    'New-FalconHorizonAzureAccount','New-FalconHorizonAzureGroup','Receive-FalconHorizonAwsScript',
    'Receive-FalconHorizonAzureScript','Remove-FalconHorizonAwsAccount','Remove-FalconHorizonAzureAccount',
    'Remove-FalconHorizonAzureGroup')
  PrivateData = @{
    PSData = @{
      Tags = @('CrowdStrike','Falcon','OAuth2','REST','API','PSEdition_Desktop','PSEdition_Core',
        'Windows','Linux','MacOS')
      LicenseUri = 'https://raw.githubusercontent.com/crowdstrike/psfalcon/master/LICENSE'
      ProjectUri = 'https://github.com/crowdstrike/psfalcon'
      IconUri = 'https://raw.githubusercontent.com/crowdstrike/psfalcon/master/icon.png'
      ReleaseNotes = 'https://github.com/crowdstrike/psfalcon/releases/tag/2.2.7'
    }
  }
}