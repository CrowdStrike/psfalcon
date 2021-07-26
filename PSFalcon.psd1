@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.1.0'
    CompatiblePSEditions = @('Desktop','Core')
    GUID                 = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'
    Author               = 'Brendan Kremian'
    CompanyName          = 'CrowdStrike'
    Copyright            = '(c) CrowdStrike. All rights reserved.'
    Description          = 'PowerShell for the CrowdStrike Falcon OAuth2 APIs'
    HelpInfoURI          = 'https://github.com/crowdstrike/psfalcon/blob/master/README.md'
    PowerShellVersion    = '5.1'
    RequiredAssemblies   = @('System.Net.Http')
    ScriptsToProcess     = @('Class/Class.ps1')
    FunctionsToExport    = @(
      # cloud-connect-aws.ps1
      'Confirm-FalconDiscoverAwsAccess',
      'Edit-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsAccount',
      'Get-FalconDiscoverAwsSettings',
      'New-FalconDiscoverAwsAccount',
      'Remove-FalconDiscoverAwsAccount',
      'Update-FalconDiscoverAwsSettings',

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
      'Edit-FalconDiscoverAzureAccount',
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
      'Add-FalconHostTag',
      'Get-FalconHost',
      'Invoke-FalconHostAction',
      'Remove-FalconHostTag',

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
      'Get-FalconInstallTokenSettings',
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
      'Get-FalconIocTotal',
      'Get-FalconProcess',

      # kubernetes-protection.ps1

      # malquery.ps1
      'Get-FalconMalQuery',
      'Get-FalconMalQueryQuota',
      'Get-FalconMalQuerySample',
      'Group-FalconMalQuerySample',
      'Invoke-FalconMalQuery',
      'Receive-FalconMalQuerySample',

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
      'Get-FalconZTA'
    )
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('CrowdStrike','Falcon','OAuth2','REST','API','PSEdition_Desktop','PSEdition_Core',
                'Windows','Linux','MacOS')
            LicenseUri   = 'https://github.com/CrowdStrike/psfalcon/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/crowdstrike/psfalcon'
            IconUri      = 
                'https://avatars.githubusercontent.com/u/54042976?s=400&u=789014ae9e1ec2204090e90711fa34dd93e5c4d1'
            ReleaseNotes = @"

THIS BRANCH IS STILL IN PROGRESS -- NOT READY FOR RELEASE

TODO Items (unfinished):

* Update remaining commands.
* Test and validate all commands.
* Migrate 'Get-Help' content to GitHub for online reference.
* Add GraphQL support for /identity-protection/ APIs.

General Changes

* Changed [Falcon] class to [ApiClient] class. The new [ApiClient] class is generic and can work with other APIs,
  which enables the use of [ApiClient] as a standalone script that can be directly called to interact with
  different APIs.

* The new [ApiClient] class includes a '.Path()' method which converts relative file paths into absolute file
  paths in a cross-platform compatible way and the '.Invoke()' method which accepts a hashtable of parameters.
  [ApiClient] will process the key/value pairs of 'Path', 'Method', 'Headers', 'Outfile', 'Formdata' and 'Body'.
  It produces a [System.Net.Http.HttpResponseMessage] which can then be converted for use with other functions.

* [ApiClient] uses a single [System.Net.Http.HttpClient] instead of rebuilding the HttpClient during each request,
  which follows Microsoft's recommendations and _greatly_ increases performance.

* Incorporated [System.Net.Http.HttpClientHandler] into [ApiClient] to enable future compatibility with Proxy
  settings and support 'SslProtocols' enforcement.

* Reorganized how CrowdStrike Falcon API authorization information is kept within the [ApiClient] object during
  script use.

* All 'public' functions (i.e. commands that users type) have been re-written to use static parameters. Dynamic
  parameters were originally used in an effort to decrease the size of the module, but they required the creation
  of a special '-Help' parameter to show help information. Switching back to static parameters allowed for the
  removal of '-Help', eliminated inconsistencies in how parameter information is displayed and increased
  performance.

* The 'Falcon' prefix has been removed from the module manifest and added directly to the function names. This
  allows users to automatically import the PSFalcon module by using one of the included commands which didn't
  work with the module prefix.

* Re-organized module manifest (PSFalcon.psd1) and reduced overall size.

* Some of the functions that were previously in the public 'scripts.ps1' have been moved into their respective
  public module scripts ('Test-FalconToken', 'Get-FalconQuickScanQuota', etc.)

* 'Public' functions have been reorganized into files that are named for their required permissions (as defined
  by Falcon API Swagger file).

* Added '.Roles' in-line comment to functions which allows users to 'Get-Help -Role <api_role>' and find
  commands that are available based on required API permission. For instance, typing 'Get-Help -Role devices:read'
  will display the 'Get-FalconHost' command, while 'Get-Help -Role devices:write' lists 'Add-FalconHostTag',
  'Invoke-FalconHostAction' and 'Remove-FalconHostTag'. Wildcards (devices:*, *:write) are supported.

New Commands

* 'Edit-FalconDiscoverAzureAccount'
* 'Edit-FalconReconNotification'
* 'Get-FalconHorizonIOAEvent'
* 'Get-FalconHorizonIOAUser'
* 'Get-FalconReconRulePreview'
* 'Receive-FalconDiscoverAzureScript'
* 'Remove-FalconReconNotification'

Command Changes

* Removed '-Help' parameter from all commands. 'Get-Help' can be used instead.

* Three different '/indicators/' API commands were previously removed by mistake and have been re-added:
  Get-FalconIocHost
  Get-FalconIocProcess
  Get-FalconIocTotal

* Request-FalconToken
  Added support for HTTP 308 redirection when requesting an OAuth2 access token. If a user attempts to
  authenticate using the wrong API hostname, the module will automatically update to the proper location and
  use that location with future requests.

  Added TLS 1.2 enforcement in 'Request-FalconToken' using [System.Net.Http.HttpClientHandler].

* Get-FalconFirewallRule
  Added '-PolicyId' parameter to return rules (in precedence order) from a specific policy.

* Invoke-FalconCommand, Invoke-FalconResponderCommand, Invoke-FalconAdminCommand
  Re-organized positioning to place '-SessionId'/'-BatchId' in front

* Invoke-FalconBatchGet
  Re-organized positioning to place '-BatchId' in front

* Remove-FalconGetFile
  Renamed 'Ids' parameter to 'Id' to reflect single value requirement

* Remove-FalconSession
  Renamed 'SessionId' to 'Id'

* Edit-FalconHorizonAzureAccount
  Added parameters to utilize additional '/cloud-connect-cspm-azure/entities/default-subscription-id/v1' endpoint

GitHub Issues

* Issue #48: Updated 'Invoke-Loop' private function with a more explicit counting method to eliminate endless
  loops caused when trying to count a single [PSCustomObject] in PowerShell 5.1.

* Issue #51: Switched 'Edit-FalconScript' and 'Send-FalconScript' to use the 'content' field rather than 'file'
  after numerous anecdotes of the 'file' parameter not working properly in different clouds.

* Issue #53: Along with 'Request-FalconToken' supporting redirection, it now retries a token request when
  presented with a HTTP 429 or 308 response. The 'Wait-RetryAfter' function was also re-written to re-calculate
  the 'X-Cs-WaitRetryAfter' time. Both of these changes seem to have eliminated the chance of a negative wait time.

* Issue #54: Updated 'Get-FalconHorizonPolicy' with additional '-Service' names.
"@
        }
    }
}