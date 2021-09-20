@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.1.4'
    CompatiblePSEditions = @('Desktop','Core')
    GUID                 = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'
    Author               = 'Brendan Kremian'
    CompanyName          = 'CrowdStrike'
    Copyright            = '(c) CrowdStrike. All rights reserved.'
    Description          = 'PowerShell for the CrowdStrike Falcon OAuth2 APIs'
    HelpInfoURI          = 'https://bk-cs.github.io/help/psfalcon/en-US'
    PowerShellVersion    = '5.1'
    RequiredAssemblies   = @('System.Net.Http')
    ScriptsToProcess     = @('Class/Class.ps1')
    FunctionsToExport    = @(
      # cloud-connect-aws.ps1
      'Confirm-FalconDiscoverAwsAccess',
      'Edit-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsSetting',
      'New-FalconDiscoverAwsAccount',
      'Remove-FalconDiscoverAwsAccount',
      'Update-FalconDiscoverAwsSetting',

      # cspm-registration.ps1
      'Edit-FalconHorizonAwsAccount',
      'Edit-FalconHorizonAzureAccount',
      'Edit-FalconHorizonPolicy',
      'Edit-FalconHorizonSchedule',
      'Get-FalconHorizonAwsAccount',
      'Get-FalconHorizonAwsLink',
      'Get-FalconHorizonAzureAccount',
      'Get-FalconHorizonIoaEvent',
      'Get-FalconHorizonIoaUser',
      'Get-FalconHorizonPolicy',
      'Get-FalconHorizonSchedule',
      'New-FalconHorizonAwsAccount',
      'New-FalconHorizonAzureAccount',
      'Receive-FalconHorizonAwsScript',
      'Receive-FalconHorizonAzureScript',
      'Remove-FalconHorizonAwsAccount',
      'Remove-FalconHorizonAzureAccount',

      # custom-ioa.ps1
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

      # d4c-registration.ps1
      'Get-FalconDiscoverAzureAccount',
      'Get-FalconDiscoverGcpAccount',
      'New-FalconDiscoverAzureAccount',
      'New-FalconDiscoverGcpAccount',
      'Receive-FalconDiscoverAzureScript',
      'Receive-FalconDiscoverGcpScript',
      'Update-FalconDiscoverAzureAccount',

      # detects.ps1
      'Edit-FalconDetection',
      'Get-FalconDetection',

      # device-control-policies.ps1
      'Edit-FalconDeviceControlPolicy',
      'Get-FalconDeviceControlPolicy',
      'Get-FalconDeviceControlPolicyMember',
      'Invoke-FalconDeviceControlPolicyAction',
      'New-FalconDeviceControlPolicy',
      'Remove-FalconDeviceControlPolicy',
      'Set-FalconDeviceControlPrecedence',

      # devices.ps1
      'Add-FalconGroupingTag',
      'Get-FalconHost',
      'Invoke-FalconHostAction',
      'Remove-FalconGroupingTag',

      # falcon-container.ps1
      'Get-FalconContainerToken',

      # falconcomplete-dashboard.ps1
      'Get-FalconCompleteAllowlist',
      'Get-FalconCompleteBlocklist',
      'Get-FalconCompleteCollection',
      'Get-FalconCompleteDetection',
      'Get-FalconCompleteEscalation',
      'Get-FalconCompleteIncident',
      'Get-FalconCompleteRemediation',

      # falconx-actors.ps1
      'Get-FalconActor',

      # falconx-indicators.ps1
      'Get-FalconIndicator',

      # falconx-reports.ps1
      'Get-FalconIntel',
      'Receive-FalconIntel',

      # falconx-rules.ps1
      'Get-FalconRule',
      'Receive-FalconRule',

      # falconx-sandbox.ps1
      'Get-FalconReport',
      'Get-FalconSubmission',
      'Get-FalconSubmissionQuota',
      'New-FalconSubmission',
      'Receive-FalconArtifact',
      'Remove-FalconReport',

      # firewall-management.ps1
      'Edit-FalconFirewallGroup',
      'Edit-FalconFirewallPolicy',
      'Edit-FalconFirewallSetting',
      'Get-FalconFirewallEvent',
      'Get-FalconFirewallField',
      'Get-FalconFirewallGroup',
      'Get-FalconFirewallPlatform',
      'Get-FalconFirewallPolicy',
      'Get-FalconFirewallPolicyMember',
      'Get-FalconFirewallRule',
      'Get-FalconFirewallSetting',
      'Invoke-FalconFirewallPolicyAction',
      'New-FalconFirewallGroup',
      'New-FalconFirewallPolicy',
      'Remove-FalconFirewallGroup',
      'Remove-FalconFirewallPolicy',
      'Set-FalconFirewallPrecedence',

      # host-group.ps1
      'Edit-FalconHostGroup',
      'Get-FalconHostGroup',
      'Get-FalconHostGroupMember',
      'Invoke-FalconHostGroupAction',
      'New-FalconHostGroup',
      'Remove-FalconHostGroup',

      # incidents.ps1
      'Get-FalconBehavior',
      'Get-FalconIncident',
      'Get-FalconScore',
      'Invoke-FalconIncidentAction',

      # installation-tokens.ps1
      'Edit-FalconInstallToken',
      'Get-FalconInstallToken',
      'Get-FalconInstallTokenEvent',
      'Get-FalconInstallTokenSetting',
      'New-FalconInstallToken',
      'Remove-FalconInstallToken',

      # ioc.ps1
      'Edit-FalconIoc',
      'Get-FalconIoc',
      'New-FalconIoc',
      'Remove-FalconIoc',

      # iocs.ps1
      'Get-FalconIocHost',
      'Get-FalconIocProcess',

      # kubernetes-protection.ps1
      'Edit-FalconContainerAwsAccount',
      'Get-FalconContainerAwsAccount',
      'Get-FalconContainerCloud',
      'Get-FalconContainerCluster',
      'Invoke-FalconContainerScan',
      'New-FalconContainerAwsAccount',
      'New-FalconContainerKey',
      'Receive-FalconContainerYaml',
      'Remove-FalconContainerAwsAccount',

      # malquery.ps1
      'Get-FalconMalQuery',
      'Get-FalconMalQueryQuota',
      'Get-FalconMalQuerySample',
      'Group-FalconMalQuerySample',
      'Invoke-FalconMalQuery',
      'Receive-FalconMalQuerySample',
      'Search-FalconMalQueryHash',

      # ml-exclusions.ps1
      'Edit-FalconMlExclusion',
      'Get-FalconMlExclusion',
      'New-FalconMlExclusion',
      'Remove-FalconMlExclusion',

      # mssp.ps1
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

      # oauth2.ps1
      'Request-FalconToken',
      'Revoke-FalconToken',
      'Test-FalconToken',

      # overwatch-dashboard.ps1
      'Get-FalconOverWatchEvent',
      'Get-FalconOverWatchDetection',
      'Get-FalconOverWatchIncident',

      # prevention-policies.ps1
      'Edit-FalconPreventionPolicy',
      'Get-FalconPreventionPolicy',
      'Get-FalconPreventionPolicyMember',
      'Invoke-FalconPreventionPolicyAction',
      'New-FalconPreventionPolicy',
      'Remove-FalconPreventionPolicy',
      'Set-FalconPreventionPrecedence',

      # psfalcon.psd1
      'Add-FalconSensorTag',
      'Export-FalconConfig',
      'Export-FalconReport',
      'Find-FalconDuplicate',
      'Get-FalconSensorTag',
      'Get-FalconQueue',
      'Import-FalconConfig',
      'Invoke-FalconDeploy',
      'Invoke-FalconRtr',
      'Remove-FalconSensorTag',
      'Send-FalconWebhook',
      'Show-FalconMap',
      'Show-FalconModule',
      'Uninstall-FalconSensor',

      # quarantine.ps1
      'Get-FalconQuarantine',
      'Invoke-FalconQuarantineAction',
      'Test-FalconQuarantineAction',

      # quick-scan.ps1
      'Get-FalconQuickScan',
      'Get-FalconQuickScanQuota',
      'New-FalconQuickScan',

      # real-time-response-admin.ps1
      'Confirm-FalconAdminCommand',
      'Edit-FalconScript',
      'Get-FalconPutFile',
      'Get-FalconScript',
      'Invoke-FalconAdminCommand',
      'Remove-FalconPutFile',
      'Remove-FalconScript',
      'Send-FalconPutFile',
      'Send-FalconScript',

      # real-time-response.ps1
      'Confirm-FalconCommand',
      'Confirm-FalconGetFile',
      'Confirm-FalconResponderCommand',
      'Get-FalconSession',
      'Invoke-FalconBatchGet',
      'Invoke-FalconCommand',
      'Invoke-FalconResponderCommand',
      'Receive-FalconGetFile',
      'Remove-FalconCommand',
      'Remove-FalconGetFile',
      'Remove-FalconSession',
      'Start-FalconSession',
      'Update-FalconSession',

      # recon-monitoring-rules.ps1
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

      # response-policies.ps1
      'Edit-FalconResponsePolicy',
      'Get-FalconResponsePolicy',
      'Get-FalconResponsePolicyMember'
      'Invoke-FalconResponsePolicyAction',
      'New-FalconResponsePolicy',
      'Remove-FalconResponsePolicy',
      'Set-FalconResponsePrecedence',

      # samplestore.ps1
      'Get-FalconSample',
      'Send-FalconSample',
      'Receive-FalconSample',
      'Remove-FalconSample',

      # self-service-ioa-exclusions.ps1
      'Edit-FalconIoaExclusion',
      'Get-FalconIoaExclusion',
      'New-FalconIoaExclusion',
      'Remove-FalconIoaExclusion',

      # sensor-installers.ps1
      'Get-FalconCcid',
      'Get-FalconInstaller',
      'Receive-FalconInstaller',

      # sensor-update-policies.ps1
      'Edit-FalconSensorUpdatePolicy',
      'Get-FalconBuild',
      'Get-FalconSensorUpdatePolicy',
      'Get-FalconSensorUpdatePolicyMember',
      'Get-FalconUninstallToken',
      'Invoke-FalconSensorUpdatePolicyAction',
      'New-FalconSensorUpdatePolicy',
      'Remove-FalconSensorUpdatePolicy',
      'Set-FalconSensorUpdatePrecedence',

      # sensor-visibility-exclusions.ps1
      'Edit-FalconSvExclusion',
      'Get-FalconSvExclusion',
      'New-FalconSvExclusion',
      'Remove-FalconSvExclusion',

      # scheduled-report.ps1
      'Get-FalconScheduledReport',
      'Receive-FalconScheduledReport',

      # spotlight-vulnerabilities.ps1
      'Get-FalconRemediation',
      'Get-FalconVulnerability',

      # streaming.ps1
      'Get-FalconStream',
      'Update-FalconStream',

      # usermgmt.ps1
      'Add-FalconRole',
      'Edit-FalconUser',
      'Get-FalconRole',
      'Get-FalconUser',
      'New-FalconUser',
      'Remove-FalconRole',
      'Remove-FalconUser',

      # zero-trust-assessment.ps1
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
            ReleaseNotes = @"
New Commands
  * psfalcon
    'Add-FalconSensorTag'
    'Get-FalconSensorTag'
    'Remove-FalconSensorTag'

Command Changes
  * Get-FalconBehavior
    Updated 'Limit' to maximum of 500 to match API.

  * Get-FalconCidGroup
    Updated 'Sort' values.

  * Get-FalconCidGroupMember
    Updated 'Sort' values.

  * Get-FalconGroupRole
    Updated 'Sort' values.

  * Get-FalconHost
    Added list of accepted 'Sort' values based on related 'Filter' values accepted by 'devices-scroll' API.

  * Get-FalconIncident
    Update 'Limit' to maximum of 500 to match API.

  * Get-FalconIoaGroup
    Updated 'Sort' values.

  * Get-FalconIoaRule
    Updated 'Sort' values.

  * Get-FalconIoc
    Updated 'Sort' values.

  * Get-FalconMemberCid
    Updated 'Sort' values.

  * Get-FalconScheduledReport
    Updated 'Sort' values.

  * Get-FalconQuarantine
    Updated 'Sort' values.

  * Get-FalconUserGroup
    Updated 'Sort' values.

  * Get-FalconUserGroupMember
    Updated 'Sort' values.

  * Invoke-FalconDeploy
    Added check for OS version and 'cd_temp' step to change to a default temporary directory (\Windows\Temp or
    /tmp) before the 'put' and 'run' commands.

  * Add-FalconHostTag
    Renamed to 'Add-FalconGroupingTag' to clarify purpose and prevent confusion with 'Add-FalconSensorTag'.

  * Remove-FalconHostTag
    Renamed to 'Remove-FalconGroupingTag' to clarify purpose and prevent confusion with 'Remove-FalconSensorTag'.

GitHub Issues
  * Issue #79: Fixed bug with 'Invoke-FalconRtr' using the 'get' command that prevented completion of 'get'
    requests and output of 'batch_get_cmd_req_id' value.
  * Issue #82: Fixed typo causing relative 'Last X days/hours' value to not be properly calculated.
  * Issue #84: Added break to abort requests when missing authorization token.
"@
        }
    }
}