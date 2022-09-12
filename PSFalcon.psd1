@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.2'
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

* cloud-connect-azure.ps1
  Get-FalconDiscoverAzureCertificate

* cloud-connect-cspm-azure.ps1
  Get-FalconHorizonAzureCertificate

* mobile-enrollment.ps1
  Invoke-FalconMobileAction

* psf-devices.ps1
  Find-FalconHostname

* user-management.ps1
  Invoke-FalconUserAction

General Changes

* Re-organized public functions into files named for their URL prefix rather than their respective Swagger
  collection (which sometimes would match the prefix and sometimes wouldn't). Because of the number of endpoints
  that fell under 'policy', it is segmented into specific files.

* The public 'users.ps1' and 'user-roles.ps1' files have been consolidated under 'user-management.ps1' and merged
  with new /user-management/ endpoints.

* Updated IPv4 regex used by 'Test-RegexValue' private function.

* Streamlined looping functionality (used with '-All' parameter). Updated all commands to output groups of
  results as they are retrieved instead of the entire result set at the end of a loop. Also verified that
  authorization tokens are properly refreshed during a long running loop.

Command Changes

* Modified 'Add-FalconSensorTag' and 'Remove-FalconSensorTag' to include the uninstall token of the target device
  and while adding and removing sensor tags with 'CsSensorSettings.exe' on Windows sensor versions v6.42 and above.

* Modified 'Get-FalconSensorTag' to return the 'FalconSensorTags' values listed in a devices API response if the
  target device is Windows sensor version 6.42 or above. If 'CsSensorSettings.exe' is updated to include a method
  to 'get' sensor tags, 'Get-FalconSensorTag' will use that method in the future.

* Removed mandatory requirement for 'TenantId' parameter within the 'Get-FalconDiscoverAzureAccount' command.

* Updated 'Invoke-FalconAlertAction' to use the new v2 endpoint which includes formatting corrections.

* Based on code provided by @SleepySysadmin, 'Invoke-FalconIdentityGraph' now has an '-All' parameter when using
  '-Query'!

  When used with a query that includes 'pageInfo{endCursor hasNextPage}', results will be paginated automatically
  and only relevant data will be output (similar to the rest of the PSFalcon commands) instead of the entire
  object.

  '-All' will automatically be added if a query begins with (`$after: Cursor) and has 'after' in the query
  parameters, as it is assumed that all results are expected.

  If 'pageInfo' is not provided in the query and '-All' is specified, a warning message will be generated.

  A  query without '-All' will produce the same results as earlier versions of the module.

* Added '-Mutation' parameter to 'Invoke-FalconIdentityGraph'.

* Updated 'Add-FalconRole', 'Edit-FalconUser', 'Get-FalconUser', 'New-FalconUser', 'Remove-FalconRole', and
  'Remove-FalconUser', to use new /user-management/ endpoints where appropriate. These commands behave as they
  did before, unless using additional parameters to signify that requests are being performed within a
  multi-CID environment.

* 'Get-FalconRole' has been updated to produce results from new /user-management/ endpoints.

Resolved Issues

* Issue #170: 'Invoke-Loop' changes should eliminate token failures during retrieval of large result sets.

* Issue #222: Updated comparison process to ensure an imported policy would be properly added to the list of
  items to be modified, whether or not it was going to be created. Removed existing copy policy operation from
  creation process.

* Issue #223: Removed extraneous 'Endpoint' definition that was generating an error.

* Issue #231: Corrected addition of 'FirewallRule' when using 'Export-FalconConfig -Item FirewallGroup'. This fix
  should also resolve issues when exporting 'HostGroup' and a singular 'exclusion' item.

* Issue #232: Re-added 'Outfile' designation for 'Path' parameter in 'Receive-FalconArtifact'. This should have
  been present and was accidentally removed in an earlier module version.
@"
        }
    }
}