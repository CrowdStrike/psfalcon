#
# Module manifest for module 'PSFalcon'
#
# Generated by: brendan@kremian.com
#
# Generated on: 2/4/2020
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PSFalcon.psm1'

# Version number of this module.
ModuleVersion = '2.0.0'

# Supported PSEditions
CompatiblePSEditions = @('Desktop','Core')

# ID used to uniquely identify this module
GUID = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'

# Author of this module
Author = 'Brendan Kremian'

# Company or vendor of this module
# CompanyName = ''

# Copyright statement for this module
Copyright = '(c) Brendan Kremian. All rights reserved.'

# Description of the functionality provided by this module
Description = "PowerShell for CrowdStrike Falcon's OAuth2 APIs"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the
# PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for
# the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module
ScriptsToProcess = @('Class/Falcon.ps1')

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry,
# use an empty array if there are no functions to export.
FunctionsToExport = @(
    # cloud-connect-aws
    'Add-AwsSettings',
    'Confirm-AwsAccess',
    'Edit-AwsAccount',
    'Get-AwsAccount',
    'Get-AwsSettings',
    'New-AwsAccount',
    'Remove-AwsAccount',

    # custom
    'Convert-CSV',
    'Get-Queue',
    'Invoke-Deploy',
    'Invoke-RTR',
    'Open-Stream',
    'Show-Map',

    # d4c-registration
    'Edit-AzureAccount',
    'Get-AzureAccount',
    'Get-AzureScript',
    'Get-GcpAccount',
    'Get-GcpScript',
    'New-AzureAccount',
    'New-GcpAccount',

    # detects
    'Edit-Detection',
    'Get-Detection',

    # device-control-policies
    'Edit-DeviceControlPolicy',
    'Get-DeviceControlPolicy',
    'Get-DeviceControlPolicyMember',
    'Invoke-DeviceControlPolicyAction',
    'New-DeviceControlPolicy',
    'Remove-DeviceControlPolicy',
    'Set-DeviceControlPrecedence',

    # event-streams
    'Get-Stream',
    'Update-Stream',

    # falconx-sandbox
    'Get-Report',
    'Get-Sample',
    'Get-Submission',
    'New-Submission',
    'Receive-Artifact',
    'Receive-Sample',
    'Remove-Report',
    'Remove-Sample',
    'Send-Sample',

    # firewall-management
    'Edit-FirewallGroup',
    'Edit-FirewallSetting',
    'Get-FirewallEvent',
    'Get-FirewallField',
    'Get-FirewallGroup',
    'Get-FirewallPlatform',
    'Get-FirewallRule',
    'Get-FirewallSetting',
    'New-FirewallGroup',
    'Remove-FirewallGroup',

    # firewall-policies
    'Edit-FirewallPolicy',
    'Get-FirewallPolicy',
    'Get-FirewallPolicyMember',
    'Invoke-FirewallPolicyAction',
    'New-FirewallPolicy',
    'Remove-FirewallPolicy',
    'Set-FirewallPrecedence',

    # host-group
    'Edit-HostGroup',
    'Get-HostGroup',
    'Get-HostGroupMember',
    'Invoke-HostGroupAction',
    'New-HostGroup',
    'Remove-HostGroup',

    # hosts
    'Get-Host',
    'Invoke-HostAction',

    # incidents
    'Get-Behavior',
    'Get-Incident',
    'Get-Score',
    'Invoke-IncidentAction',

    # installation-tokens
    'Edit-InstallToken',
    'Get-InstallToken',
    'Get-TokenEvent',
    'Get-TokenSettings',
    'New-InstallToken',
    'Remove-InstallToken',

    # intel
    'Get-Actor',
    'Get-Indicator',
    'Get-Intel',
    'Get-Rule',
    'Receive-Intel',
    'Receive-Rule',

    # iocs
    'Edit-IOC',
    'Get-IOC',
    'Get-Process',
    'New-IOC',
    'Remove-IOC',

    # malquery
    'Get-MalQuery',
    'Get-MalQueryFile',
    'Get-Quota',
    'Invoke-MalQuery',
    'Invoke-MalQueryJob',
    'Receive-MalQueryFile',

    # oauth2
    'Request-Token',
    'Revoke-Token',

    # prevention-policies
    'Edit-PreventionPolicy',
    'Get-PreventionPolicy',
    'Get-PreventionPolicyMember',
    'Invoke-PreventionPolicyAction',
    'New-PreventionPolicy',
    'Remove-PreventionPolicy',
    'Set-PreventionPrecedence',

    # real-time-response
    'Confirm-Command',
    'Confirm-GetFile',
    'Confirm-ResponderCommand',
    'Get-Session',
    'Invoke-BatchGet',
    'Invoke-Command',
    'Invoke-ResponderCommand',
    'Receive-GetFile',
    'Remove-Command',
    'Remove-GetFile',
    'Remove-Session',
    'Start-Session',
    'Update-Session',

    # real-time-response-admin
    'Confirm-AdminCommand',
    'Get-PutFile',
    'Get-Script',
    'Invoke-AdminCommand',
    'Remove-PutFile',
    'Remove-Script',
    'Send-PutFile',
    'Send-Script',

    # scanner
    'Get-Scan',
    'New-Volume',

    # sensor-download
    'Get-CCID',
    'Get-Installer',
    'Receive-Installer',

    # sensor-update-policies
    'Edit-SensorUpdatePolicy',
    'Get-Build',
    'Get-SensorUpdatePolicy',
    'Get-SensorUpdatePolicyMember',
    'Get-UninstallToken',
    'Invoke-SensorUpdatePolicyAction',
    'New-SensorUpdatePolicy',
    'Remove-SensorUpdatePolicy',
    'Set-SensorUpdatePrecedence',

    # spotlight-vulnerabilities
    'Get-Remediation',
    'Get-Vulnerability',

    # user-management
    'Add-Role',
    'Edit-User',
    'Get-Role',
    'Get-User',
    'New-User',
    'Remove-Role',
    'Remove-User'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry,
# use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry,
# use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData
# hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('CrowdStrike', 'Falcon', 'OAuth2', 'REST', 'API')

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/bk-CS/PSFalcon'

        # A URL to an icon representing this module.
        IconUri = 'https://avatars3.githubusercontent.com/u/54042976?s=460&u=de53aed783c47ef9bd9ffe9489fb77a67648eb89&v=4'

        # ReleaseNotes of this module.
        ReleaseNotes = "
        Version 2.0:

        * Rebuilt module to use an underlying template to reduce complexity and allow for re-use with other APIs (PSRestKit)
        * Functions now use dynamic parameters defined in a Json-based input file, enabling easier support of API changes
        * Changed prefix of commands from 'Cs' to 'Falcon', renamed many commands to better fit their purpose and PowerShell standards
        * Added credential handling capabilities via the Falcon class
        * Added token handling capabilities via the Falcon class, enabling support for multi-threaded PowerShell scripts
        "
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://github.com/bk-cs/PSFalcon/blob/master/README.md'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix
DefaultCommandPrefix = 'Falcon'

}