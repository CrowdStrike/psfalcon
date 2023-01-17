@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.5'
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

      # archives
      'Expand-FalconSampleArchive'
      'Get-FalconSampleArchive'
      'Get-FalconSampleExtraction'
      'Remove-FalconSampleArchive'
      'Send-FalconSampleArchive'

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
      'Get-FalconAttck'
      'Get-FalconCve'
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
      'Edit-FalconContainerAzureAccount'
      'Get-FalconContainerAwsAccount'
      'Get-FalconContainerAzureAccount'
      'Get-FalconContainerCloud'
      'Get-FalconContainerCluster'
      'Invoke-FalconContainerScan'
      'New-FalconContainerAwsAccount'
      'New-FalconContainerAzureAccount'
      'New-FalconContainerKey'
      'Receive-FalconContainerYaml'
      'Remove-FalconContainerAwsAccount'
      'Remove-FalconContainerAzureAccount'

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
            LicenseUri   = 'https://raw.githubusercontent.com/crowdstrike/psfalcon/master/LICENSE'
            ProjectUri   = 'https://github.com/crowdstrike/psfalcon'
            IconUri      = 'https://raw.githubusercontent.com/crowdstrike/psfalcon/master/icon.png'
            ReleaseNotes = 'https://github.com/crowdstrike/psfalcon/releases/tag/2.2.5'
        }
    }
}