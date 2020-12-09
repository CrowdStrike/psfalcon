#
# Module manifest for module 'psfalcon'
#
# Generated by: brendan@kremian.com
#
# Generated on: 2/4/2020
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'psfalcon.psm1'

# Version number of this module.
ModuleVersion = '2.0.0'

# Supported PSEditions
CompatiblePSEditions = @('Desktop','Core')

# ID used to uniquely identify this module
GUID = 'd893eb9f-f6bb-4a40-9caf-aaff0e42acd1'

# Author of this module
Author = 'Brendan Kremian'

# Company or vendor of this module
CompanyName = 'CrowdStrike'

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
    'Add-DiscoverAwsSettings',
    'Confirm-DiscoverAwsAccess',
    'Edit-DiscoverAwsAccount',
    'Get-DiscoverAwsAccount',
    'Get-DiscoverAwsSettings',
    'New-DiscoverAwsAccount',
    'Remove-DiscoverAwsAccount',

    # cloud-connect-azure
    'Edit-DiscoverAzureAccount',
    'Get-DiscoverAzureAccount',
    'Get-DiscoverAzureScript',
    'New-DiscoverAzureAccount',

    # cloud-connect-gcp
    'Get-DiscoverGcpAccount',
    'Get-DiscoverGcpScript',
    'New-DiscoverGcpAccount',

    # detects
    'Edit-Detection',
    'Get-Detection',

    # devices
    'Edit-HostGroup',
    'Get-Host',
    'Get-HostGroup',
    'Get-HostGroupMember',
    'Invoke-HostAction',
    'Invoke-HostGroupAction',
    'New-HostGroup',
    'Remove-HostGroup',

    # falconx
    'Get-Report',
    'Get-Submission',
    'New-Submission',
    'Receive-Artifact',
    'Remove-Report',

    # fwmgr
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

    # incidents
    'Get-Behavior',
    'Get-Incident',
    'Get-Score',
    'Invoke-IncidentAction',

    # indicators
    'Edit-IOC',
    'Get-IOC',
    'New-IOC',
    'Remove-IOC',

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

    # ioarules
    'Edit-IOAGroup',
    'Edit-IOARule',
    'Get-IOAGroup',
    'Get-IOAPlatform',
    'Get-IOARule',
    'Get-IOASeverity',
    'Get-IOAType',
    'New-IOAGroup',
    'New-IOARule',
    'Remove-IOAGroup',
    'Remove-IOARule',
    'Test-IOARule',

    # malquery
    'Get-MalQuery',
    'Get-MalQueryQuota',
    'Get-MalQuerySample',
    'Group-MalQuerySample',
    'Invoke-MalQuery',
    'Receive-MalQuerySample',

    # oauth2
    'Request-Token',
    'Revoke-Token',

    # policy
    'Edit-DeviceControlPolicy',
    'Edit-FirewallPolicy',
    'Edit-IOAExclusion',
    'Edit-MLExclusion',
    'Edit-PreventionPolicy',
    'Edit-SensorUpdatePolicy',
    'Edit-SVExclusion',
    'Get-Build',
    'Get-DeviceControlPolicy',
    'Get-DeviceControlPolicyMember',
    'Get-FirewallPolicy',
    'Get-FirewallPolicyMember',
    'Get-IOAExclusion',
    'Get-MLExclusion',
    'Get-PreventionPolicy',
    'Get-PreventionPolicyMember',
    'Get-SensorUpdatePolicy',
    'Get-SensorUpdatePolicyMember',
    'Get-SVExclusion',
    'Get-UninstallToken',
    'Invoke-DeviceControlPolicyAction',
    'Invoke-FirewallPolicyAction',
    'Invoke-PreventionPolicyAction',
    'Invoke-SensorUpdatePolicyAction',
    'New-DeviceControlPolicy',
    'New-FirewallPolicy',
    'New-IOAExclusion',
    'New-MLExclusion',
    'New-PreventionPolicy',
    'New-SensorUpdatePolicy',
    'New-SVExclusion',
    'Remove-DeviceControlPolicy',
    'Remove-FirewallPolicy',
    'Remove-IOAExclusion',
    'Remove-MLExclusion',
    'Remove-PreventionPolicy',
    'Remove-SensorUpdatePolicy',
    'Remove-SVExclusion',
    'Set-DeviceControlPrecedence',
    'Set-FirewallPrecedence',
    'Set-PreventionPrecedence',
    'Set-SensorUpdatePrecedence',

    # processes
    'Get-Process',

    # real-time-response
    'Confirm-AdminCommand',
    'Confirm-Command',
    'Confirm-GetFile',
    'Confirm-ResponderCommand',
    'Get-PutFile',
    'Get-Script',
    'Get-Session',
    'Invoke-AdminCommand',
    'Invoke-BatchGet',
    'Invoke-Command',
    'Invoke-ResponderCommand',
    'Receive-GetFile',
    'Remove-Command',
    'Remove-GetFile',
    'Remove-PutFile',
    'Remove-Script',
    'Remove-Session',
    'Send-PutFile',
    'Send-Script',
    'Start-Session',
    'Update-Session',

    # samples
    'Get-Sample',
    'Receive-Sample',
    'Remove-Sample',
    'Send-Sample',

    # scanner
    'Get-Scan',
    'New-Scan',

    # scripts
    'Export-Report',
    'Find-Duplicate',
    'Get-Queue',
    'Invoke-Deploy',
    'Invoke-RTR',
    'Open-Stream',
    'Search-MalQueryHash',
    'Show-Map',

    # sensors
    'Get-CCID',
    'Get-Installer',
    'Get-Stream',
    'Receive-Installer',
    'Update-Stream',

    # settings
    'Edit-HorizonPolicy',
    'Edit-HorizonSchedule',
    'Get-HorizonPolicy',
    'Get-HorizonSchedule',

    # spotlight
    'Get-Remediation',
    'Get-Vulnerability',

    # user-roles
    'Add-Role',
    'Get-Role',
    'Remove-Role',

    # users
    'Edit-User',
    'Get-User',
    'New-User',
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
        ProjectUri = 'https://github.com/crowdstrike/psfalcon'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module.
        ReleaseNotes = ""

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://github.com/crowdstrike/psfalcon/blob/master/README.md'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix
DefaultCommandPrefix = 'Falcon'

}