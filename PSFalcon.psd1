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
        # detects.ps1
        'Edit-FalconDetection',
        'Get-FalconDetection',

        # devices.ps1
        'Add-FalconHostTag',
        'Edit-FalconHostGroup',
        'Get-FalconHost',
        'Get-FalconHostGroup',
        'Get-FalconHostGroupMember',
        'Invoke-FalconHostAction',
        'Invoke-FalconHostGroupAction',
        'Remove-FalconHostGroup',
        'Remove-FalconHostTag',

        # falconx.ps1
        'Get-FalconReport',
        'Get-FalconSubmission',
        'Get-FalconSubmissionQuota',
        'New-FalconSubmission',
        'Receive-FalconArtifact',
        'Remove-FalconReport',

        # fwmgr.ps1
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

        # falcon-complete-dashboards.ps1
        'Get-FalconCompleteAllowlist',
        'Get-FalconCompleteBlocklist',
        'Get-FalconCompleteCollection',
        'Get-FalconCompleteDetection',
        'Get-FalconCompleteEscalation',
        'Get-FalconCompleteIncident',
        'Get-FalconCompleteRemediation',

        # incidents.ps1
        'Get-FalconBehavior',
        'Get-FalconIncident',
        'Get-FalconScore',
        'Invoke-FalconIncidentAction',

        # indicators.ps1
        'Get-FalconIOCHost',
        'Get-FalconIOCProcess',
        'Get-FalconIOCTotal',

        # installation-tokens.ps1
        'Edit-FalconInstallToken',
        'Get-FalconInstallToken',
        'Get-FalconInstallTokenEvent',
        'Get-FalconInstallTokenSettings',
        'New-FalconInstallToken',
        'Remove-FalconInstallToken',

        # intel.ps1
        'Get-FalconActor',
        'Get-FalconIndicator',
        'Get-FalconIntel',
        'Get-FalconRule',
        'Receive-FalconIntel',
        'Receive-FalconRule',

        # ioa.ps1
        'Get-FalconHorizonIOAEvent',
        'Get-FalconHorizonIOAUser',

        # ioarules.ps1
        'Edit-FalconIOAGroup',
        'Edit-FalconIOARule',
        'Get-FalconIOAGroup',
        'Get-FalconIOAPlatform',
        'Get-FalconIOARule',
        'Get-FalconIOASeverity',
        'Get-FalconIOAType',
        'New-FalconIOAGroup',
        'New-FalconIOARule',
        'Remove-FalconIOAGroup',
        'Remove-FalconIOARule',
        'Test-FalconIOARule',

        # iocs.ps1
        'Edit-FalconIOC',
        'Get-FalconIOC',
        'New-FalconIOC',
        'Remove-FalconIOC',

        # malquery.ps1
        'Get-FalconMalQuery',
        'Get-FalconMalQueryQuota',
        'Get-FalconMalQuerySample',
        'Group-FalconMalQuerySample',
        'Invoke-FalconMalQuery',
        'Receive-FalconMalQuerySample',

        # mssp.ps1
        'Add-FalconCIDGroupMember',
        'Add-FalconGroupRole',
        'Add-FalconUserGroupMember',
        'Edit-FalconCIDGroup',
        'Edit-FalconUserGroup',
        'Get-FalconCIDGroup',
        'Get-FalconCIDGroupMember',
        'Get-FalconGroupRole',
        'Get-FalconMemberCID',
        'Get-FalconUserGroup',
        'Get-FalconUserGroupMember',
        'New-FalconCIDGroup',
        'New-FalconUserGroup',
        'Remove-FalconCIDGroup',
        'Remove-FalconCIDGroupMember',
        'Remove-FalconGroupRole',
        'Remove-FalconUserGroup',
        'Remove-FalconUserGroupMember',

        # oauth2.ps1
        'Request-FalconToken',
        'Revoke-FalconToken',
        'Test-FalconToken',

        # overwatch-dashboards.ps1
        'Get-FalconOverWatchEvent',
        'Get-FalconOverWatchDetection',
        'Get-FalconOverWatchIncident',

        # processes.ps1
        'Get-FalconProcess',

        # real-time-response.ps1
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

        # recon.ps1
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

        # samples.ps1
        'Get-FalconSample',
        'Send-FalconSample',
        'Receive-FalconSample',
        'Remove-FalconSample',

        # scanner.ps1
        'Get-FalconQuickScan',
        'Get-FalconQuickScanQuota',
        'New-FalconQuickScan',

        # sensors.ps1
        'Get-FalconCCID',
        'Get-FalconInstaller',
        'Get-FalconStream',
        'Receive-FalconInstaller',
        'Update-FalconStream',

        # settings.ps1
        'Edit-FalconHorizonPolicy',
        'Edit-FalconHorizonSchedule',
        'Get-FalconHorizonPolicy',
        'Get-FalconHorizonSchedule',

        # spotlight.ps1
        'Get-FalconRemediation',
        'Get-FalconVulnerability',

        # user-roles.ps1
        'Add-FalconRole',
        'Get-FalconRole',
        'Remove-FalconRole',

        # users.ps1
        'Edit-FalconUser',
        'Get-FalconUser',
        'New-FalconUser',
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
* Issue #51: Add '-Content' switch to 'Edit-FalconScript'.
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
  removal of '-Help', and eliminates inconsistencies in how parameter information is displayed and increases
  performance.

* The 'Falcon' prefix has been removed from the module manifest and added directly to the function names. This
  allows users to automatically import the PSFalcon module by using one of the included commands which didn't
  work with the module prefix.

* Reduced overall size and re-organized module manifest (PSFalcon.psd1).

* Some of the functions that were previously in the public 'scripts.ps1' have been moved into their respective
  public module scripts ('Test-FalconToken', 'Get-FalconQuickScanQuota', etc.)

* Added '.Roles' in-line comment to functions which allows users to 'Get-Help -Role <api_role>' and find
  commands that are available based on required API permission. For instance, typing 'Get-Help -Role devices:read'
  will display the 'Get-FalconHost' command, while 'Get-Help -Role devices:write' lists 'Add-FalconHostTag',
  'Invoke-FalconHostAction' and 'Remove-FalconHostTag'. Wildcards (devices:*, *:write) are supported.

New Commands

* 'Edit-FalconReconNotification'
* 'Get-FalconHorizonIOAEvent'
* 'Get-FalconHorizonIOAUser'
* 'Get-FalconReconRulePreview'
* 'Remove-FalconReconNotification'

Command Changes

* Removed '-Help' parameter from all commands. 'Get-Help' can be used instead.
* Three different /indicators/ API commands were previously removed by mistake and have been re-added:
  Get-FalconIOCHost
  Get-FalconIOCProcess
  Get-FalconIOCTotal

* Request-FalconToken
  Added support for HTTP 308 redirection when requesting an OAuth2 access token. If a user attempts to
  authenticate using the wrong API hostname, the module will automatically update to the proper location and
  use that location with future requests.

  Added TLS 1.2 enforcement in 'Request-FalconToken' using [System.Net.Http.HttpClientHandler].

* Get-FalconFirewallRule
  Added '-PolicyId' parameter to return rules (in precedence order) from a specific policy.

* Invoke-FalconCommand, Invoke-FalconResponderCommand, Invoke-FalconAdminCommand
  Re-organized positioning to place SessionId/BatchId in front

* Invoke-FalconBatchGet
  Re-organized positioning to place BatchId in front

* Remove-FalconGetFile
  Renamed 'Ids' parameter to 'Id' to reflect single value requirement

* Remove-FalconSession
  Renamed 'SessionId' to 'Id'

GitHub Issues
* Issue #48: Updated 'Invoke-Loop' private function with a more explicit counting method to eliminate endless
  loops caused when trying to count a single [PSCustomObject] in PowerShell 5.1.

* Issue #53: Along with 'Request-FalconToken' supporting redirection, it now retries a token request when
  presented with a HTTP 429 or 308 response. The 'Wait-RetryAfter' function was also re-written to re-calculate
  the 'X-Cs-WaitRetryAfter' time. Both of these changes seem to have eliminated the chance of a negative wait time.
"@
        }
    }
}