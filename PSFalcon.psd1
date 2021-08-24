@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.1.1'
    CompatiblePSEditions = @('Desktop','Core')
    GUID                 = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'
    Author               = 'Brendan Kremian'
    CompanyName          = 'CrowdStrike'
    Copyright            = '(c) CrowdStrike. All rights reserved.'
    Description          = 'PowerShell for the CrowdStrike Falcon OAuth2 APIs'
    HelpInfoURI          = 'https://bk-cs.github.io/help/psfalcon/en-US/'
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
      'Export-FalconConfig',
      'Export-FalconReport',
      'Find-FalconDuplicate',
      'Get-FalconQueue',
      'Import-FalconConfig',
      'Invoke-FalconDeploy',
      'Invoke-FalconRtr',
      'Send-FalconWebhook',
      'Show-FalconMap',
      'Show-FalconModule',

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
General Changes

* Changed class [Falcon] to [ApiClient]. [ApiClient] is generic and can work with other APIs, which helps enable
  the use of [ApiClient] for other scripts or modules. It includes a '.Path()' method to convert relative to
  absolute filepaths, and '.Invoke()' which accepts a hashtable of parameters ('Path', 'Method', 'Headers',
  'Outfile', 'Formdata' and 'Body') and produces a [System.Net.Http.HttpResponseMessage].

* [ApiClient] now uses a single [System.Net.Http.HttpClient] and [System.Net.Http.HttpClientHandler] instead of
  rebuilding during each request, which follows Microsoft's recommendations and _greatly_ increases performance.

* PSFalcon no longer outputs to 'Write-Debug', meaning that the '-Debug' parameter will no longer provide
  any additional information. Similar output is provided to 'Write-Verbose' instead. 'Write-Verbose' output has
  been modified to include response header information that was not previously visible.

* Re-wrote and re-organized the module manifest (PSFalcon.psd1) and 'Private' functions (Private.ps1).

* Removed decimal second values from output when converting from relative time ('last 1 days') to RFC-3339.

* Added 'Confirm-String' to output 'type' based on RegEx matching. Used to validate values in commands like
  'Show-FalconMap'. This will probably be worked in to validate relevant values in other commands in the future.

* The 'Invoke-Loop' function (which powers the '-All' parameter) now produces an error when a loop ends and there
  are results remaining (API limit).

* Renamed 'Public' scripts to be organized by their permission (rather than URL path) and included some commands
  that were previously in 'Public\scripts.ps1'. Renamed 'Public\scripts.ps1' to 'Public\psfalcon.ps1'.

* All 'Public' functions (commands that users type) have been re-written to use static parameters, which removed
  the custom '-Help' parameter and supports the use of 'Get-Help'. The help content has also been moved online.
  Use 'Update-Help -Module PSFalcon' to download extended help information, including examples previously
  accessible through the GitHub-based PSFalcon Wiki.

* Added '.Roles' in-line comment to functions which allows users to 'Get-Help -Role <api_role>' and find
  commands that are available based on required API permission. For instance, typing 'Get-Help -Role devices:read'
  will display the 'Get-FalconHost' command, while 'Get-Help -Role devices:write' lists 'Add-FalconHostTag',
  'Invoke-FalconHostAction' and 'Remove-FalconHostTag'. Wildcards (devices:*, *:write) are supported.

* Modified 'meta' output from commands. Previously, if the field 'writes' was present under 'meta', the command
  result would output the sub-field 'resources_affected'. Now the command will output 'writes', leading to a
  result of '@{ writes = @{ resources_affected = [int] }}' rather than '@{ resources_affected = [int] }'. This
  will allow for the output of unexpected results, but may impact existing scripts.

* Updated the '-Array' parameter to validate objects within the array for required fields when submitting multiple
  policies/groups/rules/notifications to create/edit in one request.

* Updated commands with an '-Id' parameter to accept 'Id' from the pipeline (property and value).

New Commands

* cspm-registration
  'Edit-FalconHorizonAwsAccount'
  'Get-FalconHorizonIoaEvent'
  'Get-FalconHorizonIoaUser'

* d4c-registration
  'Receive-FalconDiscoverAzureScript'

* iocs
  'Get-FalconIocHost'
  'Get-FalconIocProcess'

* kubernetes-protection
  'Edit-FalconContainerAwsAccount'
  'Get-FalconContainerAwsAccount'
  'Get-FalconContainerCloud'
  'Get-FalconContainerCluster'
  'Invoke-FalconContainerScan'
  'Edit-FalconDiscoverAzureAccount'
  'New-FalconContainerAwsAccount'
  'New-FalconContainerKey'
  'Receive-FalconContainerYaml'
  'Remove-FalconContainerAwsAccount'

* psfalcon
  'Send-FalconWebhook'

* recon-monitoring-rules
  'Edit-FalconReconNotification'
  'Get-FalconReconRulePreview'

Command Changes
* Edit-FalconHorizonAzureAccount
  Added parameters to utilize '/cloud-connect-cspm-azure/entities/default-subscription-id/v1'.

* Edit-FalconFirewallGroup
  Updated to retrieve required values when not provided. Removed '-Tracking'.

* Edit-FalconFirewallSetting
  Renamed '-PolicyId' to '-Id'.

  Updated to retrieve required required values when not provided. Removed '-Tracking'.

  Removed '-IsDefaultPolicy' parameter as it doesn't seem to do anything.

* Edit-FalconIoaGroup
  Updated to retrieve required required values when not provided. Removed '-RulegroupVersion'.

* Edit-FalconIoaRule
  Updated to retrieve required required values when not provided. Removed '-RulegroupVersion'.

* Export-FalconConfig
  Changed archive name to 'FalconConfig_<FileDate>.zip' from 'FalconConfig_<FileDateTime>.zip'.

* Export-FalconReport
  Re-written to display results based on the object, rather than static 'properties' of a result, meaning it is
  no longer 'hard-coded' to display results a certain way. See 'Get-Help Export-FalconReport' for more explanation.

  Added '-WhatIf' support to show the resulting export rather than exporting to CSV.

* Find-FalconDuplicate
  Updated command to retrieve Host results automatically when '-Hosts' is not provided.

  Added '-Filter' parameter to use additional property to determine whether a device is a duplicate. See 'Get-Help
  Find-FalconDuplicate' for more information.

  Updated to exclude devices with empty values (both 'hostname' and any provided '-Filter').

  Updated output to include 'cid' to avoid potential problems if 'Find-FalconDuplicate' is used within a
  parent-level CID.

* Get-FalconDiscoverAwsSettings
  Renamed to 'Get-FalconDiscoverAwsSetting'.

* Get-FalconFirewallRule
  Added '-PolicyId' parameter to return rules (in precedence order) from a specific policy.

* Get-FalconInstallTokenSettings
  Renamed to 'Get-FalconInstallTokenSetting'.

* Get-FalconIocHost
  Added '-Total' to provide the functionality of the command 'Get-FalconIocTotal'.

* Get-FalconIocProcess
  Added '-Ids' to provide the functionality of the command 'Get-FalconProcess'.

* Import-FalconConfig
  Added warning when creating 'IoaGroup' to make it clear that Custom IOA Rule Groups are not assigned to
  Prevention policies (due to a limitation in data from the related APIs).

  Added '-Force' parameter to assign items to matching Host Groups (by 'name') that are present within the CID.

  Added warning messages ('[missing_assignment]') when items are unable to be created due to missing Host Groups.

* Invoke-FalconCommand, Invoke-FalconResponderCommand, Invoke-FalconAdminCommand
  Re-organized positioning to place '-SessionId' and '-BatchId' in front.

* Invoke-FalconBatchGet
  Re-organized positioning to place '-BatchId' in front.

  Changed output format so that, nstead of returning the entire Json response, the result will have the properties
  'batch_get_cmd_req_id' and 'hosts' (similar to how 'Start-FalconSession' displays a batch session result).

* Invoke-FalconDeploy
  Added '-GroupId' to run the command against a Host Group. Parameter positioning has been re-organized to
  compensate.

* Edit-FalconIoaGroup
  Updated to retrieve required values from existing rule group when not provided.

* Edit-FalconIoaRule
  Updated to retrieve required values from existing rule when not provided.

* Invoke-FalconRTR
  Added '-GroupId' to run a Real-time Response command against a Host Group. Parameter positioning has been
  re-organized to compensate.

  Removed all 'single host' Real-time Response code. Now 'Invoke-FalconRTR' always uses batch sessions, which
  should have minimal impact on the use of the command, but is easier to support.

* Remove-FalconGetFile
  Renamed '-Ids' parameter to '-Id' to reflect single value requirement.

* Remove-FalconSession
  Renamed '-SessionId' to '-Id'.

* Request-FalconToken
  Added '-Hostname' parameter and set as default. '-Cloud' is still available, but needs to be specified with a
  'us-1', 'us-2', 'eu-1' or 'us-gov-1' value.

  Added support for redirection when requesting an OAuth2 access token. PSFalcon will use 'X-Cs-Region' from
  response when provided 'Hostname' does not match.

  Added TLS 1.2 enforcement and custom 'crowdstrike-psfalcon/<version>' user-agent string.

  Added 'ClientId', 'ClientSecret', 'Hostname', and 'Cloud' as named properties that can be passed through the
  pipeline.

* Send-FalconSample
  Added support for uploading archives.

* Update-FalconDiscoverAwsSettings
  Renamed to 'Update-FalconDiscoverAwsSetting'.

GitHub Issues

* Issue #48: Updated 'Invoke-Loop' private function with a more explicit counting method to eliminate endless
  loops in PowerShell 5.1.

* Issue #51: Switched 'Edit-FalconScript' and 'Send-FalconScript' to use the 'content' field rather than 'file'.

* Issue #53: 'Wait-RetryAfter' function was re-written to re-calculate the 'X-Cs-WaitRetryAfter' time.

* Issue #54: Updated 'Get-FalconHorizonPolicy' with additional '-Service' names.

* Issue #59: Updated 'New-Falcon...Policy' commands to use 'clone_id' values in the appropriate places.

* Issue #62: Added 'user-agent' to 'Request-FalconToken'.

* Issue #63: Modified the way the 'maximum URL length' is calculated to avoid unexpected 'URL too long' HTML
  response errors from differences between cloud environments.
"@
        }
    }
}