**WARNING**: The PSFalcon modules are an independent project and not supported by CrowdStrike.

# Requirements
Requires **[PowerShell 5.1+](https://github.com/PowerShell/PowerShell#get-powershell)**

# Installation
1. Download the files in this respository
2. Extract the archive into `PSFalcon` under one of your `$env:PSModulePath` directories

# Usage
You can list all available commands through `Get-Module -Name PSFalcon` once the module has
been imported. Using the `-Help` parameter with any command will show the available parameters and
a brief description.

# Credentials
In order to interact with the Falcon OAuth2 APIs, you need a valid **[API Client ID and Secret](https://falcon.crowdstrike.com/support/api-clients-and-keys)**.
If you have previously exported your credentials into `$Home\Falcon.cred`, they will be automatically imported
when you import the PSFalcon module from the `$Home` directory.

### Exporting Credentials
You can save your credentials using the `ExportCred()` method, which will prompt you for your ID (username)
and Secret (password). Once input, the credentials will be exported to `$Home\Falcon.cred`.

This exported file is designed to be used only by the user that created it, on the device that it was created on.
Attemping to copy this file to a different device or importing it into PSFalcon under a different user account
will fail. **[Learn more about encrypted credentials here](https://adamtheautomator.com/powershell-export-xml/#Saving_an_Encrypted_Credential)**.

```powershell
PS> $Falcon.ExportCred()
```
**WARNING**: This exported file is encrypted on Windows, but it is not encrypted on MacOS or Linux. Credential
handling in PSFalcon is provided for convenience and not security.

### Importing Credentials
You can rename these files to save different credential sets and import them using the `.ImportCred()`
method. When importing credentials you only need to specify the name of the file, as it will be imported from
the local path and default to using the `.cred` extension.

```powershell
PS> $Falcon.ImportCred('Example')
Imported Example.cred
```
**WARNING**: Once imported, you must request a new token before making requests inside of the new environment.

# Tokens
### Requesting Tokens
During a PowerShell session, you must have a valid OAuth2 token in order to make requests to the Falcon APIs.

If your credentials have already been loaded, PSFalcon will request a token on your behalf when you issue a
command. Otherwise, you must request a token and provide the credentials.

```powershell
PS> Request-FalconToken
Id: <string>
Secret: <SecureString>
```

**WARNING**: Using the optional `-Id` and `-Secret` parameters with `Request-FalconToken` will result in your
credentials being displayed in plain text. This could expose them to a third party.

Once a valid OAuth2 token is received, it is cached with your credentials. Your cached token will be checked
and refreshed as needed while running PSFalcon commands.

### Alternate Clouds
By default, token requests are sent to the US cloud. The `-Cloud` parameter can be used to choose a different
destination. Your choice is saved and all requests will be sent to the chosen cloud unless a new
`Request-FalconToken` request is made specifying a new cloud.

### Child Environments
If you're in an MSSP configuration, you can target specific child environments using the `-CID` parameter
during token requests. Your choice is saved and all requests will be sent to that particular
CID unless a new `Request-FalconToken` request is made specifying a new child environment.

### Exporting Tokens
You can export a token your have requested using the `.ExportToken()` method, which creates `$Home\Falcon.token`.
Once exported, this token will be automatically loaded with PSFalcon, which enables support for multi-threaded
PowerShell scripts. If the token has expired it will be ignored.

# Commands


## /cloud-connect-aws/

### Add-FalconAwsSettings
```
# Create or update Global Settings which are applicable to all provisioned AWS accounts
  Requires cloud-connect-aws:write

  -CloudtrailId [String]
    The 12 digit AWS account which is hosting the centralized S3 bucket of containing cloudtrail logs from
    multiple accounts.
      Pattern : \d{12}

  -ExternalId [String]
    By setting this value, all subsequent accounts that are provisioned will default to using this value as their
    external ID.
```
### Confirm-FalconAwsAccess
```
# Performs an Access Verification check on the specified AWS Account IDs
  Requires cloud-connect-aws:write

  -AccountIds [Array] <Required>
    One or more AWS account identifiers
      Pattern : \d{12}
```
### Edit-FalconAwsAccount
```
# Update AWS Accounts by specifying the ID of the account and details to update
  Requires cloud-connect-aws:write

  -CloudtrailId [String]
    The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this
    field is set, it takes precedence of the settings level field.

  -CloudtrailRegion [String]
    Region where the S3 bucket containing cloudtrail logs resides.

  -ExternalId [String]
    ID assigned for use with cross account IAM role access.

  -IamRoleArn [String]
    The full arn of the IAM role created in this account to control access.

  -AccountId [String]
    12 digit AWS provided unique identifier for the account.

  -RateLimitReqs [Int32]
    Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time
    threshold.

  -RateLimitTime [Int32]
    Rate limiting setting to control the number of seconds for which -RateLimitReqs applies.
```
### Get-FalconAwsAccount
```
# Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS account
  IDs which match the filter criteria
  Requires cloud-connect-aws:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results
```
### Get-FalconAwsSettings
```
# Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts
  Requires cloud-connect-aws:read
```
### New-FalconAwsAccount
```
# Provision AWS Accounts by specifying details about the accounts to provision
  Requires cloud-connect-aws:write

  -Mode [String]
    Provisioning mode
      Accepted : cloudformation, manual

  -CloudtrailId [String]
    The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this
    field is set, it takes precedence of the settings level field.

  -CloudtrailRegion [String]
    Region where the S3 bucket containing cloudtrail logs resides.

  -ExternalId [String]
    ID assigned for use with cross account IAM role access.

  -IamRoleArn [String]
    The full arn of the IAM role created in this account to control access.

  -AccountId [String]
    12 digit AWS provided unique identifier for the account.

  -RateLimitReqs [Int32]
    Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time
    threshold.

  -RateLimitTime [Int32]
    Rate limiting setting to control the number of seconds for which -RateLimitReqs applies.
```
### Remove-FalconAwsAccount
```
# Delete a set of AWS Accounts by specifying their IDs
  Requires cloud-connect-aws:write

  -AccountIds [Array] <Required>
    One or more AWS account identifiers
```
## /custom/

### Convert-FalconCSV
```
# Format a response object to be CSV-compatible

  -Object [object] <Accepted via Pipeline>
    A result object to format
```
### Get-FalconQueue
```
# Create a report of with status of queued Real-time Response sessions
  Requires real-time-response:read, real-time-response:write, real-time-response-admin:write

  -Days [Int32]
    Number of days worth of results to retrieve [Default: 7]
```
### Invoke-FalconDeploy
```
# Deploy and run an executable using Real-time Response
  Requires real-time-response:read, real-time-response-admin:write

  -Path [String] <Required>
    Path to the executable

  -HostIds [Array] <Required>
    One or more Host identifiers
      Pattern : \w{32}

  -Arguments [String]
    Command line arguments to include upon execution

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -QueueOffline [Boolean]
    Add session to the offline queue if the host does not initialize
```
## /d4c-registration/

### Edit-FalconAzureAccount
```
# Update an Azure service account
  Requires d4c-registration:write

  -ClientId [String] <Required>
    Client identifier to use for the Service Principal associated with the Azure account
      Pattern : ^[0-9a-z-]{36}$
```
### Get-FalconAzureAccount
```
# Return information about Azure account registration
  Requires d4c-registration:read

  -SubscriptionIds [Array]
    SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are
    returned.
      Pattern : ^[0-9a-z-]{36}$

  -ScanType [String]
    Type of scan, dry or full, to perform on selected accounts
      Accepted : dry, full
```
### Get-FalconAzureScript
```
# Outputs a script to run in an Azure environment to grant access to the Falcon platform
  Requires d4c-registration:read
```
### Get-FalconGcpAccount
```
# Returns information about the current status of an GCP account.
  Requires d4c-registration:read

  -ScanType [String]
    Type of scan, dry or full, to perform on selected accounts
      Accepted : dry, full

  -ParentIds [Array]
    Parent IDs of accounts
      Pattern : \d{10,}
```
### Get-FalconGcpScript
```
# Return a script for customer to run in their cloud environment to grant us access to their GCP environment
  Requires d4c-registration:read
```
### New-FalconAzureAccount
```
# Creates a new Azure account and generates a script to grant access to the Falcon platform
  Requires d4c-registration:write

  -SubscriptionId [String]
    Azure subscription identifier
      Pattern : ^[0-9a-z-]{36}$

  -TenantId [String]
    Azure tenant identifier
```
### New-FalconGcpAccount
```
# Creates a new GCP account and generates a script to grant access to the Falcon platform
  Requires d4c-registration:write

  -ParentId [String] <Required>
    GCP parent identifier
```
## /detects/

### Edit-FalconDetection
```
# Modify the state, assignee, and visibility of detections
  Requires detects:write

  -AssignedUuid [String]
    A user identifier to use to assign the detection
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Comment [String]
    A comment to add to the detection

  -DetectionIds [Array] <Required>
    One or more detection identifiers
      Pattern : ldt:\w{32}:\w+

  -ShowInUi [Boolean]
    Display the detection in the Falcon UI

  -Status [String]
    Detection status
      Accepted : new, in_progress, true_positive, false_positive, ignored
```
### Get-FalconDetection
```
# Search for detection IDs that match a given query
  Requires detects:read

  -Limit [Int32]
    Maximum number of results per request

  -Query [String]
    Perform a generic substring search across all fields

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# List detailed detection information
  Requires detects:read

  -DetectionIds [Array] <Required>
    One or more detection identifiers
```
## /device-control-policies/

### Edit-FalconDeviceControlPolicy
```
# Update Device Control Policies by specifying the ID of the policy and details to update
  Requires device-control-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy

  -Settings [Hashtable]
    A hashtable defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Get-FalconDeviceControlPolicy
```
# Search for Device Control Policies in your environment by providing an FQL filter and paging details.
  Returns a set of Device Control Policy IDs which match the filter criteria
  Requires device-control-policies:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List detailed Device Control Policy information
  Requires device-control-policies:read

  -PolicyIds [Array] <Required>
    The IDs of the Device Control Policies to return
```
### Get-FalconDeviceControlPolicyMember
```
# Search for members of a Device Control Policy in your environment by providing an FQL filter and paging
  details. Returns a set of Agent IDs which match the filter criteria
  Requires device-control-policies:read

  -PolicyId [String]
    The ID of the Device Control Policy to search for members of

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request
```
### Invoke-FalconDeviceControlPolicyAction
```
# Perform actions on Device Control Policies
  Requires device-control-policies:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add-host-group, disable, enable, remove-host-group

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -GroupId [String]
    Host Group identifier, used when adding or removing host groups
      Pattern : \w{32}
```
### New-FalconDeviceControlPolicy
```
# Create Device Control Policies
  Requires device-control-policies:write

  -CloneId [String]
    Copy settings from an existing policy
      Pattern : \w{32}

  -Description [String]
    Policy description

  -Name [String] <Required>
    Policy name

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

  -Settings [Hashtable]
    A hashtable defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconDeviceControlPolicy
```
# Delete Device Control policies
  Requires device-control-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}
```
### Set-FalconDeviceControlPrecedence
```
# Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The first ID
  specified will have the highest precedence and the last ID specified will have the lowest. You must specify
  all non-Default Policies for a platform when updating precedence
  Requires device-control-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux
```
## /event-streams/

### Get-FalconStream
```
# Discover all event streams in your environment
  Requires streaming:read

  -AppId [String] <Required>
    Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).
      Pattern : \w{1,32}

  -Format [String]
    Format for streaming events
      Accepted : json, flatjson
```
### Open-FalconStream
```
# Export recent Stream events to Json
  Requires streaming:read
```
### Update-FalconStream
```
# Refresh an active event stream. Use the URL shown in a GET /sensors/entities/datafeed/v2 response.
  Requires streaming:read

  -ActionName [String] <Required>
    Action name. Allowed value is refresh_active_stream_session.
      Accepted : refresh_active_stream_session

  -AppId [String] <Required>
    Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).

  -Partition [Int32] <Required>
    Partition to request data for.
```
## /falconx-sandbox/

### Get-FalconReport
```
# Find sandbox reports by providing an FQL filter and paging details. Returns a set of report IDs that match
  your criteria.
  Requires falconx-sandbox:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Get a full sandbox report.
  Requires falconx-sandbox:read

  -ReportIds [Array] <Required>
    One or more report identifiers

# Get a short summary version of a sandbox report.
  Requires falconx-sandbox:read

  -ReportIds [Array] <Required>
    One or more report identifiers

  -Summary [SwitchParameter] <Required>
    Retrieve summary information
```
### Get-FalconSample
```
# Retrieve information about sandbox submission files
  Requires falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256s [Array]
    One or more SHA256 hash values
      Pattern : \w{64}
```
### Get-FalconSubmission
```
# Find submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of
  submission IDs that match your criteria.
  Requires falconx-sandbox:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Check the status of a sandbox analysis
  Requires falconx-sandbox:read

  -SubmissionIds [Array] <Required>
    One or more submission identifiers
```
### New-FalconSubmission
```
# Submit an uploaded file or a URL for sandbox analysis
  Requires falconx-sandbox:write

  -ActionScript [String]
    Runtime script for sandbox analysis
      Accepted : default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie

  -CommandLine [String]
    Command line script passed to the submitted file at runtime

  -DocumentPassword [String]
    Auto-filled for Adobe or Office files that prompt for a password

  -EnableTor [Boolean]
    Route traffic via TOR

  -EnvironmentId [String] <Required>
    Specific environment to use for analysis
      Accepted : Android, Ubuntu16_x64, Win7_x64, Win7_x86, Win10_x64

  -Sha256 [String]
    SHA256 hash value of the sample to analyze
      Pattern : \w{64}

  -SubmitName [String]
    A name for the submission file

  -SystemDate [String]
    A custom date to use in the sandbox environment
      Pattern : \d{4}-\d{2}-\d{2}

  -SystemTime [String]
    A custom time to use in the sandbox environment
      Pattern : \d{2}:\d{2}

  -Url [String]
    A web page or file URL

  -UserTags [Array]
    Tags to categorize the submission
```
### Receive-FalconArtifact
```
# Download IOC packs, PCAP files, and other analysis artifacts
  Requires falconx-sandbox:read

  -ArtifactId [String] <Required>
    Artifact identifier

  -Path [String] <Required>
    Destination Path
```
### Receive-FalconSample
```
# Retrieves the file associated with the given ID (SHA256)
  Requires falconx-sandbox:read

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256 [String] <Required>
    SHA256 hash value of the file
      Pattern : \w{64}

  -PasswordProtected [String]
    Flag whether the sample should be zipped and password protected with pass='infected'
```
### Remove-FalconReport
```
# Delete sandbox reports
  Requires falconx-sandbox:write

  -ReportId [String] <Required>
    Sandbox report identifier
```
### Remove-FalconSample
```
# Removes a sample, including file, meta and submissions from the collection
  Requires falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256 [String] <Required>
    SHA256 hash value of the file to remove
      Pattern : \w{64}
```
### Send-FalconSample
```
# Upload a sample file
  Requires falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Path [String] <Required>
    Path to the file
      Pattern : \.(acm|apk|ax|axf|bin|chm|cpl|dll|doc|docx|drv|efi|elf|eml|exe|hta|jar|js|ko|lnk|o|ocx|mod|msg|
      mui|pdf|pl|ppt|pps|pptx|ppsx|prx|ps1|psd1|psm1|pub|puff|py|rtf|scr|sct|so|svg|svr|swf|sys|tsp|vbe|vbs|
      wsf|xls|xlsx)+$

  -Filename [String]
    Filename

  -Comment [String]
    A comment to identify for other users to identify this sample

  -IsConfidential [Boolean]
    Visibility of the sample in Falcon MalQuery
```
## /firewall-management/

### Edit-FalconFirewallGroup
```
# Update name, description, or enabled status of a rule group, or create, edit, delete, or reorder rules
  Requires firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Comment [String]
    Audit log comment for this action

  -DiffOperations [Array] <Required>
    An array of hashtables containing rule or rule group changes

  -GroupId [String]
    A firewall rule group identifier

  -RuleIds [Array]
    One or more firewall rule identifiers

  -RuleVersions [Array]
    Rule version value

  -Tracking [String]
    Tracking value
```
### Edit-FalconFirewallSetting
```
# Update an identified policy container
  Requires firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -DefaultInbound [String]
    Default action for inbound traffic
      Accepted : ALLOW, DENY

  -DefaultOutbound [String]
    Default action for outbound traffic
      Accepted : ALLOW, DENY

  -Enforce [Boolean]
    Enforce this policy's rules and override the firewall settings on each assigned host

  -IsDefaultPolicy [Boolean]
    Set as default policy

  -PlatformId [String] <Required>
    Platform identifier
      Accepted : 0

  -PolicyId [String] <Required>
    Policy identifier to update

  -RuleGroupIds [Array] <Required>
    One or more rule group identifiers

  -MonitorMode [Boolean]
    Override all block rules in this policy and turn on monitoring

  -Tracking [String]
    Tracking identifier
```
### Get-FalconFirewallEvent
```
# Find all event IDs matching the query with filter
  Requires firewall-management:read

  -Query [String]
    Perform a generic substring search across all fields

  -After [String]
    A pagination token used with the Limit parameter to manage pagination of results

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List Firewall Management events
  Requires firewall-management:read

  -EventIds [Array] <Required>
    The events to retrieve, identified by ID
      Pattern : [\w-]{20}
```
### Get-FalconFirewallField
```
# Get the firewall field specification IDs for the provided platform
  Requires firewall-management:read

  -PlatformId [String]
    Get fields configuration for this platform

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Offset [Int32]
    Position to begin retrieving results

# List detailed information about Firewall Management fields
  Requires firewall-management:read

  -FieldIds [Array] <Required>
    The field identifiers to retrieve
```
### Get-FalconFirewallGroup
```
# Find all rule group IDs matching the query with filter
  Requires firewall-management:read

  -Query [String]
    Perform a generic substring search across all fields

  -After [String]
    A pagination token used with the Limit parameter to manage pagination of results

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Get rule group entities by ID. These groups do not contain their rule entites, just the rule IDs in
  precedence order.
  Requires firewall-management:read

  -GroupIds [Array] <Required>
    One or more rule group identifiers
```
### Get-FalconFirewallPlatform
```
# Get the list of platform names
  Requires firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Offset [Int32]
    Position to begin retrieving results

# Get platform names by identifier
  Requires firewall-management:read

  -PlatformIds [Array] <Required>
    One or more platform identifiers
```
### Get-FalconFirewallRule
```
# Find all rule IDs matching the query with filter
  Requires firewall-management:read

  -Query [String]
    Perform a generic substring search across all fields

  -After [String]
    A pagination token used with the Limit parameter to manage pagination of results

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Find all firewall rule IDs matching the query with filter, and return them in precedence order
  Requires firewall-management:read

  -Query [String]
    Perform a generic substring search across all fields

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

  -PolicyId [String] <Required>
    The ID of the policy container within which to query

# Get rule entities by ID (64-bit unsigned int as decimal string) or Family ID (32-character hexadecimal string)
  Requires firewall-management:read

  -RuleIds [Array] <Required>
    The rules to retrieve, identified by ID
```
### Get-FalconFirewallSetting
```
# Get policy container entities by policy ID
  Requires firewall-management:read

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}
```
### New-FalconFirewallGroup
```
# Create new rule group on a platform for a customer with a name and description, and return the ID
  Requires firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -CloneId [String]
    Copy settings from an existing policy
      Pattern : \w{32}

  -Library [String]
    If this flag is set to true then the rules will be cloned from the clone_id from the CrowdStrike Firewall
    Rule Groups Library.

  -Comment [String]
    Audit log comment for this action

  -Description [String]
    Description of the rule group

  -Enabled [Boolean] <Required>
    Status of the rule group

  -Name [String] <Required>
    Name of the rule group

  -Rules [Array]
    An array of hashtables containing rule properties
```
### Remove-FalconFirewallGroup
```
# Delete Firewall Rule Groups
  Requires firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RuleGroupIds [Array] <Required>
    One or more rule group identifiers

  -Comment [String]
    Audit log comment for this action
```
## /firewall-policies/

### Edit-FalconFirewallPolicy
```
# Update Firewall Policies by specifying the ID of the policy and details to update
  Requires firewall-management:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Get-FalconFirewallPolicy
```
# Search for Firewall Policies in your environment by providing an FQL filter and paging details. Returns a set
  of Firewall Policy IDs which match the filter criteria
  Requires firewall-management:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List detailed information about Firewall Policies
  Requires firewall-management:read

  -PolicyIds [Array] <Required>
    The IDs of the Firewall Policies to return
```
### Get-FalconFirewallPolicyMember
```
# Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details.
  Returns a set of Agent IDs which match the filter criteria
  Requires firewall-management:read

  -PolicyId [String]
    The ID of the Firewall Policy to search for members of

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request
```
### Invoke-FalconFirewallPolicyAction
```
# Perform actions on Firewall Policies
  Requires firewall-management:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add-host-group, disable, enable, remove-host-group

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -GroupId [String]
    Host Group identifier, used when adding or removing host groups
      Pattern : \w{32}
```
### New-FalconFirewallPolicy
```
# Create Firewall Policies
  Requires firewall-management:write

  -CloneId [String]
    Copy settings from an existing policy
      Pattern : \w{32}

  -Description [String]
    Policy description

  -Name [String] <Required>
    Policy name

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconFirewallPolicy
```
# Delete Firewall policies
  Requires firewall-management:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}
```
### Set-FalconFirewallPrecedence
```
# Sets the precedence of Firewall Policies based on the order of IDs specified in the request. The first ID
specified will have the highest precedence and the last ID specified will have the lowest. You must specify all
non-Default Policies for a platform when updating precedence
  Requires firewall-management:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux
```
## /host-group/

### Edit-FalconHostGroup
```
# Update Host Groups by specifying the ID of the group and details to update
  Requires host-group:write

  -AssignmentRule [String]
    The new assignment rule of the group. Note: If the group type is static, this field cannot be updated manually

  -Description [String]
    The new description of the group

  -GroupId [String] <Required>
    The id of the group to update
      Pattern : \w{32}

  -Name [String]
    The new name of the group

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Get-FalconHostGroup
```
# Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of
  Host Group IDs which match the filter criteria
  Requires host-group:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List detailed information about Host Groups
  Requires host-group:read

  -GroupIds [Array] <Required>
    The IDs of the Host Groups to return
      Pattern : \w{32}
```
### Get-FalconHostGroupMember
```
# Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns
  a set of Agent IDs which match the filter criteria
  Requires host-group:read

  -GroupId [String] <Required>
    The ID of the Host Group to search for members of
      Pattern : \w{32}

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request
```
### Invoke-FalconHostGroupAction
```
# Perform the specified action on the Host Groups specified in the request
  Requires host-group:write

  -ActionName [String] <Required>
    The action to perform on the target Host Groups
      Accepted : add-hosts, remove-hosts

  -GroupId [String] <Required>
    Host group identifier
      Pattern : \w{32}

  -FilterName [String] <Required>
    FQL filter name
      Accepted : device_id, domain, external_ip, groups, hostname, local_ip, mac_address, os_version, ou,
      platform_name, site, system_manufacturer

  -FilterValue [Array] <Required>
    One or more values for use with the FQL filter
```
### New-FalconHostGroup
```
# Create Host Groups
  Requires host-group:write

  -AssignmentRule [String]
    An FQL filter expression to dynamically assign hosts

  -Description [String]
    Group description

  -GroupType [String] <Required>
    Group type
      Accepted : static, dynamic

  -Name [String] <Required>
    Group name

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconHostGroup
```
# Delete Host Groups
  Requires host-group:write

  -GroupIds [Array] <Required>
    One or more group identifiers
      Pattern : \w{32}
```
## /hosts/

### Get-FalconHost
```
# Search for hosts
  Requires devices:read

  -Offset [String]
    A pagination token used with the Limit parameter to manage pagination of results

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Limit [Int32]
    Maximum number of results per request

# Retrieve hidden hosts that match the provided filter criteria.
  Requires devices:read

  -Offset [String]
    Position to begin retrieving results

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Limit [Int32]
    Maximum number of results per request

  -Hidden [SwitchParameter] <Required>
    Search for hidden hosts

# List detailed Host information
  Requires devices:read

  -HostIds [Array] <Required>
    The host agentIDs used to get details on
      Pattern : \w{32}
```
### Invoke-FalconHostAction
```
# Perform actions on Hosts
  Requires devices:write

  -ActionName [String] <Required>
    The action to perform on the target Hosts
      Accepted : contain, lift_containment, hide_host, unhide_host

  -HostIds [Array] <Required>
    One or more Host identifiers
      Pattern : \w{32}
```
## /incidents/

### Get-FalconBehavior
```
# Search for behaviors by providing an FQL filter, sorting, and paging details
  Requires incidents:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# List detailed information about behaviors
  Requires incidents:read

  -BehaviorIds [Array] <Required>
    One or more behavior identifiers
```
### Get-FalconIncident
```
# Search for incidents by providing an FQL filter, sorting, and paging details
  Requires incidents:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# List detailed information about Incidents
  Requires incidents:read

  -IncidentIds [Array] <Required>
    One or more Incident identifiers
```
### Get-FalconScore
```
# List CrowdScore values
  Requires incidents:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results
```
### Invoke-FalconIncidentAction
```
# Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident
  name or description
  Requires incidents:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add_tag, delete_tag, update_description, update_name, update_status

  -ActionValue [String] <Required>
    Value for the chosen action

  -IncidentIds [Array] <Required>
    One or more Incident identifiers
      Pattern : inc:\w{32}:\w{32}

  -UpdateDetects [Boolean]
    Update the status of 'new' related detections

  -OverwriteDetects [String]
    Replace existing status for related detections
```
## /installation-tokens/

### Edit-FalconInstallToken
```
# Updates one or more tokens. Use this endpoint to edit labels, change expiration, revoke, or restore.
  Requires installation-tokens:write

  -TokenIds [Array] <Required>
    One or more token identifiers
      Pattern : \w{32}

  -ExpiresTimestamp [String]
    The token's expiration time (RFC-3339). Null, if the token never expires.

  -Label [String]
    The token label.

  -Revoked [Boolean]
    Set to true to revoke the token, false to un-revoked it.
```
### Get-FalconInstallToken
```
# Search for tokens by providing an FQL filter and paging details.
  Requires installation-tokens:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# Gets the details of one or more tokens by id.
  Requires installation-tokens:read

  -TokenIds [Array]
    One or more token identifiers
      Pattern : \w{32}
```
### Get-FalconTokenEvent
```
# Search for installation token audit events
  Requires installation-tokens:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# Retrieve installation token audit events
  Requires installation-tokens:read

  -EventIds [Array]
    One or more event identifiers
```
### Get-FalconTokenSettings
```
# List installation token settings
  Requires installation-tokens:read
```
### New-FalconInstallToken
```
# Creates a token.
  Requires installation-tokens:write

  -ExpiresTimestamp [String]
    The token's expiration time (RFC-3339). Null, if the token never expires.

  -Label [String]
    The token label.
```
### Remove-FalconInstallToken
```
# Deletes a token immediately. To revoke a token, use PATCH /installation-tokens/entities/tokens/v1 instead.
  Requires installation-tokens:write

  -TokenIds [Array] <Required>
    One or more token identifiers
      Pattern : \w{32}
```
## /intel/

### Get-FalconActor
```
# Get actor IDs that match provided FQL filters.
  Requires falconx-actors:read

  -Query [String]
    Perform a generic substring search across all fields

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List detailed information about Actors
  Requires falconx-actors:read

  -ActorIds [Array] <Required>
    The IDs of the actors you want to retrieve.

  -Fields [Array]
    The fields to return, or a predefined collection name surrounded by two underscores
```
### Get-FalconIndicator
```
# Get indicators IDs that match provided FQL filters.
  Requires falconx-indicators:read

  -Limit [Int32]
    Maximum number of results per request

  -Query [String]
    Perform a generic substring search across all fields

  -IncludeDeleted [Boolean]
    Include both published and deleted indicators

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# List detailed information about Indicators
  Requires falconx-indicators:read

  -IndicatorIds [Array] <Required>
    One or more indicator identifiers
```
### Get-FalconIntel
```
# Get report IDs that match provided FQL filters.
  Requires falconx-reports:read

  -Query [String]
    Perform a generic substring search across all fields

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# List detailed information about Intel Reports
  Requires falconx-reports:read

  -ReportIds [Array] <Required>
    The IDs of the reports you want to retrieve.

  -Fields [Array]
    The fields to return, or a predefined collection name surrounded by two underscores
```
### Get-FalconRule
```
# Search for rule IDs that match provided filter criteria.
  Requires falconx-rules:read

  -Limit [Int32]
    Maximum number of results per request

  -Name [Array]
    Search by rule title.

  -Type [String] <Required>
    The rule news report type
      Accepted : snort-suricata-master, snort-suricata-update, snort-suricata-changelog, yara-master,
      yara-update, yara-changelog, common-event-format, netwitness

  -Description [Array]
    Substring match on description field.

  -Tags [Array]
    Search for rule tags.

  -MinCreatedDate [Int32]
    Filter results to those created on or after a certain date.

  -MaxCreatedDate [String]
    Filter results to those created on or before a certain date.

  -Query [String]
    Perform a generic substring search across all fields

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Offset [Int32]
    Position to begin retrieving results

# List detailed information about Intel Rules
  Requires falconx-rules:read

  -RuleIds [Array] <Required>
    The ids of rules to return.

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved
```
### Receive-FalconIntel
```
# Download an Intel Report PDF
  Requires falconx-reports:read

  -ReportId [String] <Required>
    The ID of the report you want to download as a PDF.

  -Path [String] <Required>
    Destination Path
      Pattern : \.pdf$
```
### Receive-FalconRule
```
# Download a specific threat intelligence ruleset zip file
  Requires falconx-rules:read

  -RuleId [Int32] <Required>
    Rule set identifier

  -Path [String] <Required>
    Destination Path
      Pattern : \.zip$

# Download the latest threat intelligence ruleset zip file
  Requires falconx-rules:read

  -Path [String] <Required>
    Destination Path
      Pattern : \.zip$

  -Type [String] <Required>
    Rule news report type
      Accepted : snort-suricata-master, snort-suricata-update, snort-suricata-changelog, yara-master,
      yara-update, yara-changelog, common-event-format, netwitness
```
## /iocs/

### Edit-FalconIOC
```
# Update a custom IOC
  Requires iocs:write

  -ExpirationDays [Int32]
    Number of days before expiration (for 'domain', 'ipv4', and 'ipv6')

  -Policy [String]
    Action to take when a host observes the custom IOC
      Accepted : detect, none

  -ShareLevel [String]
    Custom IOC visibility level ['red']
      Accepted : red

  -Source [String]
    Custom IOC source

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value

  -Description [String]
    Custom IOC description
```
### Get-FalconIOC
```
# Search the custom IOCs in your customer account
  Requires iocs:read

  -Type [String]
    Type of indicator
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String]
    The string representation of the indicator

  -FromExpirationTimestamp [String]
    Find custom IOCs created after this time (RFC-3339 timestamp)

  -ToExpirationTimestamp [String]
    Find custom IOCs created before this time (RFC-3339 timestamp)

  -Policy [String]
    Custom IOC policy type ['detect', 'none']
      Accepted : detect, none

  -Sources [String]
    The source where this indicator originated. This can be used for tracking where this indicator was defined.

  -ShareLevels [String]
    The level at which the indicator will be shared. Currently only red share level (not shared) is supported,
    indicating that the IOC isn't shared with other FH customers.
      Accepted : red

  -CreatedBy [String]
    The user or API client who created the Custom IOC

  -DeletedBy [String]
    The user or API client who deleted the Custom IOC

  -IncludeDeleted [Boolean]
    Include deleted IOCs

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

# Get detailed information about an IOC
  Requires iocs:read

  -Type [String] <Required>
    Indicator type ['sha256', 'md5', 'domain', 'ipv4', 'ipv6']
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Indicator value

# List the number of hosts that have observed a custom IOC
  Requires iocs:read

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value

# List the host identifiers that have observed a custom IOC
  Requires iocs:read

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Hosts [SwitchParameter] <Required>
    Retrieve host identifiers for hosts that have observed a custom IOC

  -Limit [Int32]
    Maximum number of results per request

# Search for processes associated with a custom IOC
  Requires iocs:read

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

  -Processes [SwitchParameter] <Required>
    Retrieve process identifiers for a host that has observed a custom IOC

  -HostId [String] <Required>
    Target Host identifier
      Pattern : \w{32}
```
### Get-FalconProcess
```
# Search for processes associated with a custom IOC
  Requires iocs:read

# Retrieve detail about a process
  Requires iocs:read

  -ProcessIds [Array] <Required>
    One or more process identifiers
```
### New-FalconIOC
```
# Create custom IOCs
  Requires iocs:write

  -Description [String]
    Custom IOC description

  -ExpirationDays [Int32]
    Number of days before expiration (for 'domain', 'ipv4', and 'ipv6')

  -Policy [String] <Required>
    Action to take when a host observes the custom IOC
      Accepted : detect, none

  -ShareLevel [String]
    Custom IOC visibility level
      Accepted : red

  -Source [String]
    Custom IOC source

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconIOC
```
# Delete a custom IOC
  Requires iocs:write

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
```
### Show-FalconMap
```
# Graph Indicators
  No permissions required

  -Indicators [Array] <Required>
    Indicators to graph
      Pattern : (sha256|md5|domain|ipv4|ipv6):.*
```
## /malquery/

### Get-FalconMalQuery
```
# Check the status and results of a MalQuery request
  Requires malquery:read

  -QueryIds [Array] <Required>
    MalQuery request identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```
### Get-FalconMalQueryFile
```
# Retrieve indexed files metadata by their hash
  Requires malquery:read

  -FileIds [Array] <Required>
    The file SHA256.
```
### Get-FalconQuota
```
# Get information about search and download quotas in your environment
  Requires malquery:read
```
### Invoke-FalconMalQuery
```
# Search MalQuery for a combination of hex patterns and strings
  Requires malquery:write

  -FilterFileTypes [Array]
    File types to include with the results
      Pattern : (cdf|cdfv2|cjava|dalvik|doc|docx|elf32|elf64|email|html|hwp|java.arc|lnk|macho|pcap|pdf|pe32|
      pe64|perl|ppt|pptx|python|pythonc|rtf|swf|text|xls|xlsx)

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results per request

  -MaxDate [String]
    Limit results to files first seen after this date
      Pattern : \d{4}/\d{2}/\d{2}

  -MaxSize [String]
    Maximum file size, specified in bytes or multiples of KB/MB/GB

  -MinDate [String]
    Limit results to files first seen after this date
      Pattern : \d{4}/\d{2}/\d{2}

  -MinSize [String]
    Minimum file size, specified in bytes or multiples of KB/MB/GB

  -PatternType [String] <Required>
    Pattern type
      Accepted : hex, ascii, wide

  -PatternValue [String] <Required>
    Pattern value

# Schedule a YARA-based search for execution
  Requires malquery:write

  -FilterFileTypes [Array]
    File types to include with the results
      Pattern : (cdf|cdfv2|cjava|dalvik|doc|docx|elf32|elf64|email|html|hwp|java.arc|lnk|macho|pcap|pdf|pe32|pe64|
      perl|ppt|pptx|python|pythonc|rtf|swf|text|xls|xlsx)

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results per request

  -MaxDate [String]
    Limit results to files first seen after this date
      Pattern : \d{4}/\d{2}/\d{2}

  -MaxSize [String]
    Maximum file size, specified in bytes or multiples of KB/MB/GB

  -MinDate [String]
    Limit results to files first seen after this date
      Pattern : \d{4}/\d{2}/\d{2}

  -MinSize [String]
    Minimum file size, specified in bytes or multiples of KB/MB/GB

  -Hunt [SwitchParameter] <Required>
    Schedule a YARA-based search

  -YaraRule [String] <Required>
    A YARA rule that defines your search

# Search MalQuery quickly, but with more potential for false positives.
  Requires malquery:write

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results per request

  -PatternType [String] <Required>
    Pattern type
      Accepted : hex, ascii, wide

  -PatternValue [String] <Required>
    Pattern value

  -Fuzzy [SwitchParameter] <Required>
    Perform a fuzzy search
```
### Invoke-FalconMalQueryJob
```
# Schedule samples for download from MalQuery
  Requires malquery:write

  -SampleIds [Array] <Required>
    List of sample sha256 ids
```
### Receive-FalconMalQueryFile
```
# Download a file indexed by MalQuery using its SHA256 value
  Requires malquery:read

  -Sha256 [String] <Required>
    SHA256 value of the sample

  -Path [String] <Required>
    Destination Path

# Download a zip containing Malquery samples (password: infected)
  Requires malquery:read

  -Path [String] <Required>
    Destination Path

  -JobId [String] <Required>
    Sample job identifier
```
## /oauth2/

### Request-FalconToken
```
# Generate an OAuth2 access token
  No permissions required

  -Id [String]
    The API client ID to authenticate your API requests

  -Secret [String]
    The API client secret to authenticate your API requests

  -CID [String]
    For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID

  -Cloud [String]
    Destination CrowdStrike cloud
      Accepted : eu-1, us-gov-1, us-1, us-2
```
### Revoke-FalconToken
```
# Revoke your current OAuth2 access token before the end of its standard lifespan
  No permissions required
```
## /prevention-policies/

### Edit-FalconPreventionPolicy
```
# Update Prevention Policies by specifying the ID of the policy and details to update
  Requires prevention-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy

  -Settings [Array]
    An array of hashtables defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Get-FalconPreventionPolicy
```
# Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a
  set of Prevention Policy IDs which match the filter criteria
  Requires prevention-policies:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Retrieve a set of Prevention policies
  Requires prevention-policies:read

  -PolicyIds [Array] <Required>
    Prevention policy identifiers
```
### Get-FalconPreventionPolicyMember
```
# Search for members of a Prevention Policy in your environment by providing an FQL filter and paging details.
  Returns a set of Agent IDs which match the filter criteria
  Requires prevention-policies:read

  -PolicyId [String]
    The ID of the Prevention Policy to search for members of

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request
```
### Invoke-FalconPreventionPolicyAction
```
# Perform actions on Prevention Policies
  Requires prevention-policies:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add-host-group, disable, enable, remove-host-group

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -GroupId [String]
    Host Group identifier, used when adding or removing host groups
      Pattern : \w{32}
```
### New-FalconPreventionPolicy
```
# Create Prevention Policies
  Requires prevention-policies:write

  -CloneId [String]
    Copy settings from an existing policy
      Pattern : \w{32}

  -Description [String]
    Policy description

  -Name [String] <Required>
    Policy name

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

  -Settings [Array]
    An array of hashtables defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconPreventionPolicy
```
# Delete Prevention policies
  Requires prevention-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}
```
### Set-FalconPreventionPrecedence
```
# Sets the precedence of Prevention Policies based on the order of IDs specified in the request. The first ID
  specified will have the highest precedence and the last ID specified will have the lowest. You must specify all
  non-Default Policies for a platform when updating precedence
  Requires prevention-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux
```
## /real-time-response/

### Confirm-FalconCommand
```
# Get status of an executed command on a single host.
  Requires real-time-response:read

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved
```
### Confirm-FalconGetFile
```
# Get a list of files for the specified RTR session.
  Requires real-time-response:write

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

# Retrieve the status of a 'get' command issued to a batch Real-time Response session
  Requires real-time-response:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchGetCmdReqId [String] <Required>
    Batch 'get' command request identifier
```
### Confirm-FalconResponderCommand
```
# Check the status of an Active Responder Real-time Response command
  Requires real-time-response:write

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved
```
### Get-FalconSession
```
# Get a list of session_ids.
  Requires real-time-response:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Get queued session metadata by session ID
  Requires real-time-response:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -SessionIds [Array] <Required>
    One or more session identifiers

  -Queue [SwitchParameter] <Required>
    Lists information about sessions in the offline queue

# Get session metadata by session id.
  Requires real-time-response:read

  -SessionIds [Array] <Required>
    One or more session identifiers
```
### Invoke-FalconBatchGet
```
# Send a 'get' request to a batch Real-time Response session
  Requires real-time-response:write

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Path [String] <Required>
    Full path to the file to be retrieved from each host

  -OptionalHosts [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}
```
### Invoke-FalconCommand
```
# Issue a Real-time Response command to a session
  Requires real-time-response:read

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, csrutil, env, eventlog, filehash, getsid, help, history, ifconfig, ipconfig, ls,
      mount, netstat, ps, reg query, users

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

# Issue a Real-time Response command to a batch session
  Requires real-time-response:read

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, csrutil, env, eventlog, filehash, getsid, help, history, ifconfig, ipconfig, ls,
      mount, netstat, ps, reg query, users

  -Arguments [String]
    Arguments to include with the command

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}
```
### Invoke-FalconResponderCommand
```
# Issue a Real-time Response command to a session using Active Responder permissions
  Requires real-time-response:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history,
      ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg query, reg set, reg delete,
      reg load, reg unload, restart, rm, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

# Issue a Real-time Response command to a batch session using Active Responder permissions
  Requires real-time-response:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history,
      ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg query, reg set, reg delete,
      reg load, reg unload, restart, rm, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}
```
### Receive-FalconGetFile
```
# Download a file extracted through a Real-time Response 'get' request
  Requires real-time-response:write

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256 [String] <Required>
    SHA256 value of the extracted file

  -Path [String] <Required>
    Full destination path for .7z file
      Pattern : \.7z$
```
### Remove-FalconCommand
```
# Delete a queued session command
  Requires real-time-response:read

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```
### Remove-FalconGetFile
```
# Delete a RTR session file.
  Requires real-time-response:write

  -FileId [String] <Required>
    File identifier

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```
### Remove-FalconSession
```
# Delete a session.
  Requires real-time-response:read

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```
### Start-FalconSession
```
# Initialize a Real-time Response session
  Requires real-time-response:read

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}

  -Origin [String]
    Optional comment about the creation of the session

  -QueueOffline [Boolean]
    Add session to the offline queue if the host does not initialize

# Initialize a Real-time Response session on multiple hosts
  Requires real-time-response:read

  -QueueOffline [Boolean]
    Add sessions in this batch to the offline queue if the hosts do not initialize

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -ExistingBatchId [String]
    Add hosts to an existing batch session
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -HostIds [Array] <Required>
    One or more host identifiers
      Pattern : \w{32}
```
### Update-FalconSession
```
# Refresh a session timeout on a single host.
  Requires real-time-response:read

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}

  -QueueOffline [Boolean]
    Add session to the offline queue

# Refresh a batch Real-time Response session, to avoid hitting the default timeout of 10 minutes
  Requires real-time-response:read

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RemoveHostIds [Array]
    One or more Host identifiers to remove from the batch session
      Pattern : \w{32}
```
## /real-time-response-admin/

### Confirm-FalconAdminCommand
```
# Get status of an executed RTR administrator command on a single host.
  Requires real-time-response-admin:write

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved
```
### Get-FalconPutFile
```
# Get a list of put-file ID's that are available to the user for the `put` command.
  Requires real-time-response-admin:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Get put-files based on the ID's given. These are used for the RTR `put` command.
  Requires real-time-response-admin:write

  -FileIds [Array] <Required>
    One or more file identifiers
```
### Get-FalconScript
```
# Get a list of custom-script ID's that are available to the user for the `runscript` command.
  Requires real-time-response-admin:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command.
  Requires real-time-response-admin:write

  -ScriptIds [Array] <Required>
    One or more script identifiers
```
### Invoke-FalconAdminCommand
```
# Issue a Real-time Response command to a session using Admin permissions
  Requires real-time-response-admin:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history,
      ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg query, reg set,
      reg delete, reg load, reg unload, restart, rm, run, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

# Issue a Real-time Response command to a batch session using Admin permissions
  Requires real-time-response-admin:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history,
      ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg query, reg set,
      reg delete, reg load, reg unload, restart, rm, run, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -Timeout [Int32]
    Length of time to wait for a result, in seconds

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}
```
### Remove-FalconPutFile
```
# Delete a put-file based on the ID given.  Can only delete one file at a time.
  Requires real-time-response-admin:write

  -FileId [String] <Required>
    File identifier
```
### Remove-FalconScript
```
# Delete a custom-script based on the ID given.  Can only delete one script at a time.
  Requires real-time-response-admin:write

  -FileId [String] <Required>
    Script identifier
```
### Send-FalconPutFile
```
# Upload a new put-file to use for the RTR `put` command.
  Requires real-time-response-admin:write

  -Path [String] <Required>
    File to upload

  -Description [String] <Required>
    A description of the file

  -Name [String]
    Optional name to use for the script

  -Comment [String]
    A comment for the audit log
```
### Send-FalconScript
```
# Upload a new custom-script to use for the RTR `runscript` command.
  Requires real-time-response-admin:write

  -Path [String] <Required>
    Script to upload

  -Description [String] <Required>
    A description of the script

  -Name [String]
    Optional name to use for the script

  -Comment [String]
    A comment for the audit log

  -PermissionType [String] <Required>
    Permission level [private: uploader only, group: admins, public: admins and active responders]
      Accepted : private, group, public

  -Platform [Array]
    Operating system platform [default: windows]
      Accepted : windows, mac
```
## /scanner/

### Get-FalconScan
```
# Find the volume identifiers for submitted scans
  Requires quick-scan:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Check the status of a submitted scan
  Requires quick-scan:read

  -ScanIds [Array] <Required>
    One or more volume scan identifiers
      Pattern : \w{32}_\w{32}
```
### New-FalconVolume
```
# Submit a volume of files for scanning
  Requires quick-scan:write

  -Sha256s [Array] <Required>
    One or more SHA256 hash values to submit as a volume scan
```
## /sensor-download/

### Get-FalconCCID
```
# Get CCID to use with sensor installers
  Requires sensor-installers:read
```
### Get-FalconInstaller
```
# Get sensor installer IDs by provided query
  Requires sensor-installers:read

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

# Get sensor installer details by provided SHA256 IDs
  Requires sensor-installers:read

  -FileIds [Array] <Required>
    The IDs of the installers
```
### Receive-FalconInstaller
```
# Download a sensor installer
  Requires sensor-installers:read

  -InstallerId [String] <Required>
    SHA256 hash value of the installer to download
      Pattern : \w{64}

  -Path [String] <Required>
    Destination path
      Pattern : \.(deb|exe|html|pkg|rpm)+$
```
## /sensor-update-policies/

### Edit-FalconSensorUpdatePolicy
```
# Update Sensor Update Policies by specifying the ID of the policy and details to update
  Requires sensor-update-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -Name [String]
    The new name to assign to the policy

  -Settings [Hashtable]
    A hashtable defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Get-FalconBuild
```
# Retrieve available builds for use with Sensor Update Policies
  Requires sensor-update-policies:read

  -Platform [String]
    The platform to return builds for
      Accepted : linux, mac, windows
```
### Get-FalconSensorUpdatePolicy
```
# Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. Returns
  a set of Sensor Update Policy IDs which match the filter criteria
  Requires sensor-update-policies:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Search for Sensor Update Policies with additional support for uninstall protection in your environment by
  providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter
  criteria
  Requires sensor-update-policies:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request

# Retrieve a set of Sensor Update Policies with additional support for uninstall protection by specifying
  their IDs
  Requires sensor-update-policies:read

  -PolicyIds [Array] <Required>
    The IDs of the Sensor Update Policies to return
```
### Get-FalconSensorUpdatePolicyMember
```
# Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging
  details. Returns a set of Agent IDs which match the filter criteria
  Requires sensor-update-policies:read

  -PolicyId [String]
    The ID of the Sensor Update Policy to search for members of

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results per request
```
### Get-FalconUninstallToken
```
# Reveal an uninstall token for a specific device, or use 'MAINTENANCE' to reveal the bulk token
  Requires sensor-update-policies:write

  -AuditMessage [String]
    A comment to append to the audit log

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}
```
### Invoke-FalconSensorUpdatePolicyAction
```
# Perform actions on Sensor Update Policies
  Requires sensor-update-policies:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add-host-group, disable, enable, remove-host-group

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -GroupId [String]
    Host Group identifier, used when adding or removing host groups
      Pattern : \w{32}
```
### New-FalconSensorUpdatePolicy
```
# Create Sensor Update Policies
  Requires sensor-update-policies:write

  -Description [String]
    The description to use when creating the policy

  -Name [String] <Required>
    The name to use when creating the policy

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

  -Settings [Hashtable]
    A hashtable defining policy settings

  -Array [Array]
    An array of hashtables to submit in a single request
```
### Remove-FalconSensorUpdatePolicy
```
# Delete Sensor Update policies
  Requires sensor-update-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}
```
### Set-FalconSensorUpdatePrecedence
```
# Sets the precedence of Sensor Update Policies based on the order of IDs specified in the request. The first
  ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify
  all non-Default Policies for a platform when updating precedence
  Requires sensor-update-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux
```
## /spotlight-vulnerabilities/

### Get-FalconRemediation
```
# Get information about remediations
  Requires spotlight-vulnerabilities:read

  -RemediationIds [Array] <Required>
    Remediation identifiers
      Pattern : \w{32}
```
### Get-FalconVulnerability
```
# Search for vulnerability identifiers
  Requires spotlight-vulnerabilities:read

  -After [String]
    A pagination token used with the Limit parameter to manage pagination of results

  -Limit [Int32]
    Maximum number of results per request

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Filter [String]
    An FQL filter expression

  -Sort [String]
    Property and direction to sort results

# Get details on vulnerabilities by providing one or more IDs
  Requires spotlight-vulnerabilities:read

  -VulnerabilityIds [Array] <Required>
    One or more vulnerability identifiers
```
## /user-management/

### Add-FalconRole
```
# Assign one or more roles to a user
  Requires usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RoleIds [Array] <Required>
    One or more roles to assign
```
### Edit-FalconUser
```
# Modify an existing user's first or last name
  Requires usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -FirstName [String]
    User's first name

  -LastName [String]
    User's last name
```
### Get-FalconRole
```
# List user role identifiers
  Requires usermgmt:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

# Get info about a role
  Requires usermgmt:read

  -RoleIds [Array] <Required>
    One or more role identifiers

# Show role IDs of roles assigned to a user
  Requires usermgmt:read

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```
### Get-FalconUser
```
# List all user identifiers
  Requires usermgmt:read

  -Names [SwitchParameter]
    Retrieve usernames (typically email addresses) rather than user identifiers

  -Detailed [SwitchParameter]
    Retrieve detailed information

# Get detailed information about a user
  Requires usermgmt:read

  -UserIds [Array] <Required>
    One or more user identifiers
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

# Retrieve a user identifier by providing a username (typically an email address)
  Requires usermgmt:read

  -Username [Array] <Required>
    Email address or username
```
### New-FalconUser
```
# Create a user
  Requires usermgmt:write

  -FirstName [String]
    User's first name

  -LastName [String]
    User's last name

  -Password [String]
    The user's password. If left blank, the system will generate an email asking them to set their
    password (recommended)

  -Username [String] <Required>
    A username; typically an email address
```
### Remove-FalconRole
```
# Revoke one or more roles from a user
  Requires usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RoleIds [Array] <Required>
    One or more roles
```
### Remove-FalconUser
```
# Delete a user
  Requires usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}
```