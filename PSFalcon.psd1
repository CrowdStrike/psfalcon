@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.1'
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
      # alerts.ps1
      'Get-FalconAlert',
      'Invoke-FalconAlertAction',

      # cloud-connect-aws.ps1
      'Confirm-FalconDiscoverAwsAccess',
      'Edit-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsSetting',
      'New-FalconDiscoverAwsAccount',
      'Remove-FalconDiscoverAwsAccount',
      'Update-FalconDiscoverAwsSetting',

      # container-security.ps1
      'Get-FalconContainerAssessment',
      'Get-FalconContainerSensor',
      'Remove-FalconRegistryCredential',
      'Request-FalconRegistryCredential',
      'Remove-FalconContainerImage',
      'Show-FalconRegistryCredential',

      # cspm-registration.ps1
      'Edit-FalconHorizonAwsAccount',
      'Edit-FalconHorizonAzureAccount',
      'Edit-FalconHorizonPolicy',
      'Edit-FalconHorizonSchedule',
      'Get-FalconHorizonAwsAccount',
      'Get-FalconHorizonAwsLink',
      'Get-FalconHorizonAzureAccount',
      'Get-FalconHorizonIoa',
      'Get-FalconHorizonIoaEvent',
      'Get-FalconHorizonIoaUser',
      'Get-FalconHorizonIom',
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

      # discover.ps1
      'Get-FalconAsset',

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

      # filevantage.ps1
      'Get-FalconFimChange',

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

      # identity-graphql.ps1
      'Invoke-FalconIdentityGraph',

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

      # message-center.ps1
      'Add-FalconCompleteActivity',
      'Edit-FalconCompleteCase',
      'New-FalconCompleteCase',
      'Get-FalconCompleteActivity',
      'Get-FalconCompleteCase',
      'Receive-FalconCompleteAttachment',
      'Send-FalconCompleteAttachment',

      # ml-exclusions.ps1
      'ConvertTo-FalconMlExclusion',
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

      # psf-config.ps1
      'Export-FalconConfig',
      'Import-FalconConfig',

      # psf-devices.ps1
      'Add-FalconSensorTag',
      'Find-FalconDuplicate',
      'Get-FalconSensorTag',
      'Remove-FalconSensorTag',
      'Uninstall-FalconSensor',

      # psf-humio.ps1
      'Register-FalconEventCollector',
      'Send-FalconEvent',
      'Show-FalconEventCollector',
      'Unregister-FalconEventCollector',

      # psf-output.ps1
      'Export-FalconReport',
      'Send-FalconWebhook',
      'Show-FalconMap',
      'Show-FalconModule',

      # psf-policies.ps1
      'Copy-FalconDeviceControlPolicy',
      'Copy-FalconFirewallPolicy',
      'Copy-FalconPreventionPolicy',
      'Copy-FalconResponsePolicy',
      'Copy-FalconSensorUpdatePolicy',

      # psf-real-time-response.ps1
      'Get-FalconQueue',
      'Invoke-FalconDeploy',
      'Invoke-FalconRtr',

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

      # scheduled-report.ps1
      'Get-FalconScheduledReport',
      'Invoke-FalconScheduledReport',
      'Receive-FalconScheduledReport',
      'Redo-FalconScheduledReport',

      # self-service-ioa-exclusions.ps1
      'ConvertTo-FalconIoaExclusion',
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
      'Get-FalconKernel',
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

      # spotlight-vulnerabilities.ps1
      'Get-FalconRemediation',
      'Get-FalconVulnerability',
      'Get-FalconVulnerabilityLogic',

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
            ReleaseNotes = "@
New Commands

* alerts.ps1
  Get-FalconAlert
  Invoke-FalconAlertAction

* container-upload.ps1
  Get-FalconContainerAssessment
  Remove-FalconContainerImage

* container-security.ps1
  Get-FalconContainerSensor
  Remove-FalconRegistryCredential
  Request-FalconRegistryCredential
  Show-FalconRegistryCredential

General Changes

* Enabled the use of '-WhatIf' and '-Confirm' by adding 'ShouldProcess' support across the module. This also
  required the renaming of the existing '-Confirm' parameter to '-Wait' for 'Invoke-FalconAdminCommand',
  'Invoke-FalconBatchGet', 'Invoke-FalconCommand' and 'Invoke-FalconResponderCommand'.

* Updated ApiClient.Invoke() to remove blank verbose output when 'Headers' are not specified during a request.

* Created 'Get-ContainerUrl' to convert cached Hostname value into a valid 'container-upload' URL value when using
  'container-upload' commands.

* Created 'New-ShouldMessage' function to generate the output message when '-Confirm' or '-WhatIf' is used with
  a command.

* Added 'HostUrl' parameter to 'Invoke-Falcon' to force the use of 'container-upload' base URL instead of the
  cached Falcon API hostname.

* Updated 'Test-FqlStatement' private function to allow for the use of either single or double quotation marks.

* Updated RegEx patterns when validating input to look for a more restrictive list of characters to better match
  expected values.

* Various comment-based help text updates and typo corrections.

* The online help files (accessed using 'Update-Help') for PSFalcon are no longer valid for this and future
  releases as comment-based help has been included for individual commands. Using 'Get-Help <command> -Online'
  for any PSFalcon command will link you directly to the PSFalcon Wiki which includes command examples that were
  previously provided through the online help.

* Renamed 'falcon-container.ps1' to 'container-security.ps1'. Removed 'container-upload.ps1' and moved commands
  into 'container-security.ps1'.

* Modified private 'Get-ContainerUrl' function to include a 'Registry' switch to output the Falcon container
  registry URL for related commands.

Command Changes

* Add-FalconRole, Remove-FalconRole
  Updated to use 'Get-FalconRole' to determine valid 'Id' values for auto-completion.

* Add-FalconGroupingTag, Add-FalconSensorTag, Remove-FalconGroupingTag, Remove-FalconSensorTag
  Renamed 'Tags' to 'Tag'. Retained 'Tags' as an alias. This was missed in the v2.2.0 release.

* Edit-FalconIoc, New-FalconIoc
  Added 'android' and 'ios' as valid 'Platform' values and 'MobileAction' parameter.

* Export-FalconConfig
  Updated to include the export of 'platform_default' policies.

* Export-FalconReport
  Updated to force the creation of the same columns for every result.

* Get-FalconContainerToken
  Command has been removed and replaced with 'Request-FalconRegistryCredential' which combines requests for your
  Falcon container registry password, username (modified CID value) and authorization token, which are cached
  within the PSFalcon module, similar to 'Request-FalconToken'.

* Get-FalconFirewallRule
  Updated to output rules in order of specified 'Id' values when using the 'Id' parameter. This solves an issue
  where rules are provided in order of the 'id' property when they were retrieved using the 'family' property and
  are returned out of order (in respect to the 'family' values).

* Get-FalconScript, Get-FalconPutFile
  Updated to use new v2 endpoints which include workflow-related schema and information.

* Get-FalconUninstallToken
  Added 'Include' parameter.

* Import-FalconConfig
  Renamed 'Force' parameter to 'AssignExisting'. Retained 'Force' as an alias.

  Added 'ModifyDefault' to modify 'platform_default' policies to match settings from import for specified values.

  Added 'ModifyExisting' to modify existing items to match settings from import for specified values.

* Invoke-FalconBatchGet
  Added 'batch_get_cmd_req_id' to each individual host result.

* Invoke-FalconDeploy
  Added 'tgz' as a supported 'Archive' format.

  Added 'cmd' as a supported 'File' and 'Run' format using 'cmd.exe' in place of 'powershell.exe'.

  Modified 'Run' to execute a custom script that launches a secondary process when provided with a script file.
  This ensures that the process will execute and not wait for completion (similar to a regular executable when
  being used with the 'run' Real-time Response command). Standard output and error streams are redirected to
  'stdout.log' and 'stderr.log' within the temporary 'FalconDeploy' directory.

  Added 'Include' parameter.

* Invoke-FalconIncidentAction
  Added 'unassign' and 'update_assigned_to_v2' actions.

* Invoke-FalconRtr
  Updated to create Real-time Response sessions in groups of 10,000.

* New-FalconSubmission
  Added 'macOS_10.15' for parameter 'EnvironmentId'.

* Uninstall-FalconSensor
  Added timeout value (120 seconds) to reduce the chance of no 'status' value being returned.

  Added 'Include' parameter.

Resolved Issues

* Issue #211: Added try/catch to 'Get-FalconHost' when using '-Include group_names' to suppress errors when
  hosts have no groups.

* Issue #212: Added actions to 'Invoke-FalconIncidentAction'.
@"
        }
    }
}