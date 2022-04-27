@{
    RootModule           = 'PSFalcon.psm1'
    ModuleVersion        = '2.2.0'
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
            ReleaseNotes = @"
  New Commands

    * spotlight-vulnerabilities.ps1
      'Get-FalconVulnerabilityLogic'

  General Changes

    * Re-added basic help information to each command. This will increase module size, but will eliminate the
      need to 'Update-Help' to get descriptions for each command, its parameters and the required API
      permission(s).

    * Thanks to some knowledge shared by @kra-ts, PowerShell pipeline support is now cross-module and no longer
      restricted to specific commands!

      Before this release, PSFalcon supported pipeline input when a command accepted a single 'id'. With these
      changes, PSFalcon collects multiple 'ids' passed through the pipeline, groups them and sends appropriately
      sized API requests.

      This change also required the re-positioning of many parameters, the addition of aliases, and the majority of
      [array] parameters being converted into [string[]] or [int[]]. When it was logically possible, [array] values
      were also converted into [object[]] to allow for the processing of both 'id' and 'detailed' values.

    * Warning messages have been added when hosts are not included in a batch Real-time Response session
      ('Start-FalconSession') or when Real-time Response commands produce errors ('Invoke-FalconCommand',
      'Invoke-FalconResponderCommand', 'Invoke-FalconAdminCommand', 'Invoke-FalconBatchGet') so it will be more
      obvious what happened when hosts are missing from the final result that was passed through the pipeline.

    * Renamed plural parameters ('Ids') to singular ('Id') to follow PowerShell best practices. Each updated
      parameter kept maintains the plural version as an alias (or the original parameter name when switching to the
      singular was not possible due to incompatibilities with PowerShell) to prevent errors with existing scripts.

    * Modified commands to use the alias values for parameters instead of the 'Fields' variable that was used to
      to rename parameters to fit API submission structure. Removing 'Fields' also enabled the removal of the
      private function 'Update-FieldName'.

    * When applicable, the 'Id' parameter attributes were modified to ensure that 'Get-Help' properly displayed
      that the parameter name needs to be explicitly included.

    * Added case enforcement to all 'ValidateSet' values. This ensures that proper case is used with parameters
      that have a pre-defined list of accepted values and preventing errors from the resulting API.

    * Added 'raw_array' as a field to be used when defining the format of a 'body' submission inside of a PSFalcon
      command. Using it will instruct the module to create a 'body' object that has a base [array] value containing
      the object properties to be converted to Json.

    * Updated 'Build-Formdata' private function to attempt to gather file content for the 'content' field, or
      supply the original value if that fails. This change was made to allow 'Send-FalconScript' to use a file
      path or string-based script content.

    * Created 'Assert-Extension' private function to validate a given file extension when using 'Receive' commands.

    * Renamed 'Add-Property' private function to 'Set-Property' and updated it to add a property when it doesn't
      exist, or update the value if it does exist.

    * Created 'Test-OutFile' private function to validate the presence of an existing file and generate error
      messages when using 'Receive' commands.

    * Moved verbose output of 'body' and 'formdata' payloads from 'Build-Content' to ApiClient.Invoke() during a
      request. This ensures that individual submissions are displayed, rather than the initial submission before it
      has been broken up into groups.

    * Moved verbose output of Header keys and values within an API response from 'Write-Result' to
      ApiClient.Invoke(). 'Write-Result' continues to display the 'meta' Json values due to the addition of an
      internal function called 'Write-Meta'.

    * Added '-Force' function to the following commands to overwrite an existing file when present:
      'Export-FalconConfig'
      'Receive-FalconHorizonAwsScript'
      'Receive-FalconHorizonAzureScript'
      'Receive-FalconDiscoverAzureScript'
      'Receive-FalconDiscoverGcpScript'
      'Receive-FalconIntel'
      'Receive-FalconRule'
      'Receive-FalconArtifact'
      'Receive-FalconContainerYaml'
      'Receive-FalconMalQuerySample'
      'Receive-FalconCompleteAttachment'
      'Receive-FalconGetFile'
      'Receive-FalconSample'
      'Receive-FalconScheduledReport'
      'Receive-FalconInstaller'

    * Updated commands ('Import-FalconConfig', 'Export-FalconReport', 'Get-FalconQueue', 'Invoke-FalconDeploy')
      that output to CSV to send their results to 'Write-Output' when unable to write to CSV.

  Command Changes

    * 'Confirm-FalconGetFile', 'Remove-FalconGetFile'
      Updated to use v2 API endpoint that includes upload progress.

    * 'ConvertTo-FalconMlExclusion', 'ConvertTo-FalconIoaExclusion'
      Commands have been corrected to properly produce individual exclusions for each relevant behavior within a
      detection (rather than one exclusion with values from multiple behaviors).

    * 'Edit-FalconFirewallSetting', 'Edit-FalconHorizonPolicy'
      Renamed '-PolicyId' to '-Id'.

    * 'Export-FalconConfig'
      Now includes 'Script' (Real-time Response scripts) as an exportable item.

      Output filename now contains a 'FileDateTime' timestamp instead of simply 'FileDate'. This was done to
      match changes made to 'Import-FalconConfig'.

    * 'Find-FalconDuplicate'
      Updated to accommodate multiple 'Filter' values.

    * 'Get-FalconAsset'
      Added '-Account' and '-Login' switch parameters to toggle access of Falcon Discover user account assets
      and user login events.

      Added '-Include' to append login events both the default hardware asset and user account output.

    * 'Get-FalconFirewallPolicy'
      Re-added the 'policy_id' in the 'settings' sub-object that is created when using '-Include settings'. This
      was originally removed for being redundant, but needed to be restored to be utilized by the 
      'Copy-FalconFirewallPolicy' command.

    * 'Get-FalconHorizonIoa', 'Get-FalconHorizonIoaEvent', 'Get-FalconHorizonIoaUser', 'Get-FalconHorizonIom'
      Removed 'Mandatory' status for '-CloudPlatform', instead populating it if 'AwsAccountId' (or 'AccountId',
      in the case of 'Get-FalconHorizonIom'), 'AzureSubscriptionId', or 'AzureTenantId' are provided. Without one
      of the four values, the command will produce an exception.

    * 'Get-FalconHorizonIoaEvent', 'Get-FalconHorizonIoaUser'
      Replaced '-AccountId' with '-AwsAccountId' and added '-AzureSubscriptionId' and '-AzureTenantId' to match
      'Get-FalconHorizonIoa'.

    * 'Get-FalconHorizonIom'
      Renamed parameter '-AwsAccountId' to '-AccountId', which accepts an AWS account ID or GCP Project Number
      value. Also corrected the accepted '-Status' value 'recurring' to 'reoccurring'.

    * 'Get-FalconHost'
      '-Detailed' output will no longer be forced when using '-Include group_names', and instead will include
      'device_id' and 'groups'. Using '-Detailed' and '-Include group_names' maintains full output.

      Added 'online_state' to '-Include' to retrieve detail from new 'online status' API.

      Added '-State' switch to be used with '-Id' to retrieve detail from the new 'online status' API.

    * 'Get-FalconQueue'
      Updated command to write progress to host stream instead of verbose stream.

    * 'Get-FalconVulnerability'
      Added 'evaluation_logic' to the 'Facet' parameter.

    * 'Import-FalconConfig'
      Completely re-written to utilize the pipeline and excluded items (with the reason they were excluded) are
      now included within the resulting CSV output.

      Now includes 'Script' (Real-time Response scripts) as an importable item.

      Output filename now contains a 'FileDateTime' timestamp instead of simply 'FileDate'. This was done because
      verbosity of the output was increased and appending to an existing file would cause output problems.

      Removed warning message that was generated when no items were created because the CSV output now displays
      both excluded and created items.

    * 'Invoke-FalconBatchGet', 'Invoke-FalconCommand', 'Invoke-FalconAdminCommand', 'Invoke-FalconResponderCommand'
      Added a new '-Confirm' parameter to confirm and retrieve the output from both single-host commands and batch
      'get' commands.

      'Invoke-FalconAdminCommand' and 'Invoke-FalconResponderCommand' will now redirect to 'Invoke-FalconBatchGet'
      when used to 'get' within a multi-host session.

      Each of the commands now appends 'batch_id' to the output of commands issued within a batch session.

    * 'Invoke-FalconCommand', 'Invoke-FalconAdminCommand', 'Invoke-FalconResponderCommand', 'Invoke-FalconRtr'
      Split the 'eventlog' command into 'eventlog backup', 'eventlog export', 'eventlog list', and 'eventlog view'.

    * 'Invoke-FalconDeploy'
      Contribution from @soggysec: Changed '-Path' to '-File' and added '-Archive' (with the corresponding '-Run'
      parameter) to allow for a file or archive to be specified. If 'Archive' is used, Real-time Response will
      'run' the file specified by '-Run', allowing the deployment of files that require additional files to be
      present in order to execute.

      Added 'mkdir' step to create a temporary folder in order to ensure that a unique file will be 'put' and 'run'
      each time, instead of failing when a previous 'put' occurred. CSV output was slightly modified as a result.

    * 'New-FalconDeviceControlPolicy', 'New-FalconFirewallPolicy', 'New-FalconPreventionPolicy'
      Removed the '-CloneId' parameter from the following commands due to inconsistencies in created policies. The
      'Copy-Falcon...Policy' commands continue to be available for use instead.

    * 'Request-FalconToken'
      Contribution from @kra-ts: Added support for a CCID value in the '-MemberCid' parameter which leads to the
      checksum value being silently dropped but the CID itself being accepted.

    * 'Send-FalconScript'
      Updated to allow 'Path' to contain string based script content or a path to a file.

    * 'Start-FalconSession'
      Now uses '-Id' to define both single-host and multi-host sessions. When host identifier values are passed in
      the pipeline the command will default to a multi-host (batch) session. Additionally, this command now appends
      'batch_id' to each host that was successfully initiated within a multi-host session.
"@
        }
    }
}