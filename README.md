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
Create or update Global Settings which are applicable to all provisioned AWS accounts
  Endpoint   : POST /cloud-connect-aws/entities/settings/v1
  Permission : cloud-connect-aws:write

  -CloudtrailBucketOwnerId [String]
    The 12 digit AWS account which is hosting the centralized S3 bucket of containing cloudtrail logs from multiple accounts.
      Pattern : \d{12}

  -StaticExternalId [String]
    By setting this value, all subsequent accounts that are provisioned will default to using this value as their external ID.

```
### Confirm-FalconAwsAccess
```
Performs an Access Verification check on the specified AWS Account IDs
  Endpoint   : POST /cloud-connect-aws/entities/verify-account-access/v1
  Permission : cloud-connect-aws:write

  -AccountIds [Array] <Required>
    One or more AWS account identifiers
      Pattern : \d{12}

```
### Edit-FalconAwsAccount
```
Update AWS Accounts by specifying the ID of the account and details to update
  Endpoint   : PATCH /cloud-connect-aws/entities/accounts/v1
  Permission : cloud-connect-aws:write

  -CloudtrailBucketOwnerId [String]
    The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field.

  -CloudtrailBucketRegion [String]
    Region where the S3 bucket containing cloudtrail logs resides.

  -ExternalId [String]
    ID assigned for use with cross account IAM role access.

  -IamRoleArn [String]
    The full arn of the IAM role created in this account to control access.

  -AccountId [String]
    12 digit AWS provided unique identifier for the account.

  -RateLimitReqs [Int32]
    Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time threshold.

  -RateLimitTime [Int32]
    Rate limiting setting to control the number of seconds for which -RateLimitReqs applies.

```
### Get-FalconAwsAccount
```
Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS account IDs which match the filter criteria
  Endpoint   : GET /cloud-connect-aws/queries/accounts/v1
  Permission : cloud-connect-aws:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 500

  -Offset [Int32]
    Position to begin retrieving results

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS accounts which match the filter criteria
  Endpoint   : GET /cloud-connect-aws/combined/accounts/v1
  Permission : cloud-connect-aws:read

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 500

  -Offset [Int32]
    Position to begin retrieving results

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

```
### Get-FalconAwsSettings
```
Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts
  Endpoint   : GET /cloud-connect-aws/combined/settings/v1
  Permission : cloud-connect-aws:read

```
### New-FalconAwsAccount
```
Provision AWS Accounts by specifying details about the accounts to provision
  Endpoint   : POST /cloud-connect-aws/entities/accounts/v1
  Permission : cloud-connect-aws:write

  -Mode [String]
    Provisioning mode
      Accepted : cloudformation, manual

  -CloudtrailBucketOwnerId [String]
    The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field.

  -CloudtrailBucketRegion [String]
    Region where the S3 bucket containing cloudtrail logs resides.

  -ExternalId [String]
    ID assigned for use with cross account IAM role access.

  -IamRoleArn [String]
    The full arn of the IAM role created in this account to control access.

  -AccountId [String]
    12 digit AWS provided unique identifier for the account.

  -RateLimitReqs [Int32]
    Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time threshold.

  -RateLimitTime [Int32]
    Rate limiting setting to control the number of seconds for which -RateLimitReqs applies.

```
### Remove-FalconAwsAccount
```
Delete a set of AWS Accounts by specifying their IDs
  Endpoint   : DELETE /cloud-connect-aws/entities/accounts/v1
  Permission : cloud-connect-aws:write

  -AccountIds [Array] <Required>
    One or more AWS account identifiers

```
## /d4c-registration/

### Edit-FalconAzureAccount
```
Update an Azure service account
  Endpoint   : PATCH /cloud-connect-azure/entities/client-id/v1
  Permission : d4c-registration:write

  -ClientId [String] <Required>
    Client identifier to use for the Service Principal associated with the Azure account
      Pattern : ^[0-9a-z-]{36}$

```
### Get-FalconAzureAccount
```
Return information about Azure account registration
  Endpoint   : GET /cloud-connect-azure/entities/account/v1
  Permission : d4c-registration:read

  -SubscriptionIds [Array]
    SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned.
      Pattern : ^[0-9a-z-]{36}$

  -ScanType [String]
    Type of scan, dry or full, to perform on selected accounts
      Accepted : dry, full

```
### Get-FalconAzureScript
```
Outputs a script to run in an Azure environment to grant access to the Falcon platform
  Endpoint   : GET /cloud-connect-azure/entities/user-scripts/v1
  Permission : d4c-registration:read

```
### Get-FalconGcpAccount
```
Returns information about the current status of an GCP account.
  Endpoint   : GET /cloud-connect-gcp/entities/account/v1
  Permission : d4c-registration:read

  -ScanType [String]
    Type of scan, dry or full, to perform on selected accounts
      Accepted : dry, full

  -ParentIds [Array]
    Parent IDs of accounts
      Pattern : \d{10,}

```
### Get-FalconGcpScript
```
Return a script for customer to run in their cloud environment to grant us access to their GCP environment
  Endpoint   : GET /cloud-connect-gcp/entities/user-scripts/v1
  Permission : d4c-registration:read

```
### New-FalconAzureAccount
```
Creates a new Azure account and generates a script to grant access to the Falcon platform
  Endpoint   : POST /cloud-connect-azure/entities/account/v1
  Permission : d4c-registration:write

  -SubscriptionId [String]
    Azure subscription identifier
      Pattern : ^[0-9a-z-]{36}$

  -TenantId [String]
    Azure tenant identifier

```
### New-FalconGcpAccount
```
Creates a new GCP account and generates a script to grant access to the Falcon platform
  Endpoint   : POST /cloud-connect-gcp/entities/account/v1
  Permission : d4c-registration:write

  -ParentId [String] <Required>
    GCP parent identifier

```
## /detects/

### Edit-FalconDetection
```
Modify the state, assignee, and visibility of detections
  Endpoint   : PATCH /detects/entities/detects/v2
  Permission : detects:write

  -AssignedToUuid [String]
    A user identifier to use to assign the detection
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Comment [String]
    A comment to add to the detection

  -DetectionIds [Array]
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
Search for detection IDs that match a given query
  Endpoint   : GET /detects/queries/detects/v1
  Permission : detects:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 9999

  -Sort [String]
    Property and direction to sort results
      Accepted : adversary.id|asc, adversary.id|desc, devices.hostname|asc, devices.hostname|desc, first_behavior|asc, last_behavior|asc, last_behavior|desc, max_confidence|asc, max_confidence|desc, max_severity|asc, max_severity|desc

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Search all detection metadata for the provided string

List detailed detection information
  Endpoint   : POST /detects/entities/summaries/GET/v1
  Permission : detects:read

  -DetectionIds [Array] <Required>
    One or more detection identifiers

```
## /device-control-policies/

### Edit-FalconDeviceControlPolicy
```
Update Device Control Policies by specifying the ID of the policy and details to update
  Endpoint   : PATCH /policy/entities/device-control/v1
  Permission : device-control-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy

  -Settings [Hashtable]
    A hashtable defining policy settings


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to update using a single request

```
### Get-FalconDeviceControlPolicy
```
Search for Device Control Policies in your environment by providing an FQL filter and paging details. Returns a set of Device Control Policy IDs which match the filter criteria
  Endpoint   : GET /policy/queries/device-control/v1
  Permission : device-control-policies:read

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

Search for members of a Device Control Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria
  Endpoint   : GET /policy/queries/device-control-members/v1
  Permission : device-control-policies:read

  -Members [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

  -PolicyId [String]
    The ID of the Device Control Policy to search for members of

List detailed Device Control Policy information
  Endpoint   : GET /policy/entities/device-control/v1
  Permission : device-control-policies:read

  -PolicyIds [Array] <Required>
    The IDs of the Device Control Policies to return

```
### Invoke-FalconDeviceControlPolicyAction
```
Perform actions on Device Control Policies
  Endpoint   : POST /policy/entities/device-control-actions/v1
  Permission : device-control-policies:write

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
Create Device Control Policies
  Endpoint   : POST /policy/entities/device-control/v1
  Permission : device-control-policies:write

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


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to create using a single request

```
### Remove-FalconDeviceControlPolicy
```
Delete Device Control policies
  Endpoint   : DELETE /policy/entities/device-control/v1
  Permission : device-control-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}

```
### Set-FalconDeviceControlPrecedence
```
Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
  Endpoint   : POST /policy/entities/device-control-precedence/v1
  Permission : device-control-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

```
## /event-streams/

### Get-FalconStream
```
Discover all event streams in your environment
  Endpoint   : GET /sensors/entities/datafeed/v2
  Permission : streaming:read

  -AppId [String] <Required>
    Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).
      Pattern : \w{1,32}
      Minimum : 1
      Maximum : 32

  -Format [String]
    Format for streaming events
      Accepted : json, flatjson

```
### Open-FalconStream
``````
### Update-FalconStream
```
Refresh an active event stream. Use the URL shown in a GET /sensors/entities/datafeed/v2 response.
  Endpoint   : POST /sensors/entities/datafeed-actions/v1/<partition>
  Permission : streaming:read

  -ActionName [String] <Required>
    Action name. Allowed value is refresh_active_stream_session.
      Accepted : refresh_active_stream_session

  -AppId [String] <Required>
    Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).
      Minimum : 1
      Maximum : 32

  -Partition [Int32] <Required>
    Partition to request data for.

```
## /falconx-sandbox/

### Get-FalconReport
```
Find sandbox reports by providing an FQL filter and paging details. Returns a set of report IDs that match your criteria.
  Endpoint   : GET /falconx/queries/reports/v1
  Permission : falconx-sandbox:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

Get a short summary version of a sandbox report.
  Endpoint   : GET /falconx/entities/report-summaries/v1
  Permission : falconx-sandbox:read

  -Summary [SwitchParameter] <Required>
    

  -ReportIds [Array] <Required>
    ID of a summary. Find a summary ID from the response when submitting a malware sample or search with `/falconx/queries/reports/v1`.

Get a full sandbox report.
  Endpoint   : GET /falconx/entities/reports/v1
  Permission : falconx-sandbox:read

  -ReportIds [Array] <Required>
    ID of a report. Find a report ID from the response when submitting a malware sample or search with `/falconx/queries/reports/v1`.

```
### Get-FalconSample
```
Retrieve information about sandbox submission files
  Endpoint   : POST /samples/queries/samples/GET/v1
  Permission : falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256s [Array]
    

```
### Get-FalconSubmission
```
Find submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of submission IDs that match your criteria.
  Endpoint   : GET /falconx/queries/submissions/v1
  Permission : falconx-sandbox:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

Check the status of a sandbox analysis. Time required for analysis varies but is usually less than 15 minutes.
  Endpoint   : GET /falconx/entities/submissions/v1
  Permission : falconx-sandbox:read

  -SubmissionIds [Array] <Required>
    ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with `/falconx/queries/submissions/v1`.

```
### New-FalconSubmission
```
Submit an uploaded file or a URL for sandbox analysis. Time required for analysis varies but is usually less than 15 minutes.
  Endpoint   : POST /falconx/entities/submissions/v1
  Permission : falconx-sandbox:write

  -ActionScript [String]
    
      Accepted : default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie

  -CommandLine [String]
    
      Minimum : 1
      Maximum : 2048

  -DocumentPassword [String]
    
      Minimum : 1
      Maximum : 32

  -EnableTor [Boolean]
    

  -EnvironmentId [String] <Required>
    
      Accepted : Android, Ubuntu16_x64, Win7_x64, Win7_x86, Win10_x64

  -Sha256 [String]
    
      Pattern : \w{64}
      Minimum : 64
      Maximum : 64

  -SubmitName [String]
    

  -SystemDate [String]
    
      Pattern : \d{4}-\d{2}-\d{2}

  -SystemTime [String]
    
      Pattern : \d{2}:\d{2}

  -Url [String]
    

  -UserTags [Array]
    

```
### Receive-FalconArtifact
```
Download IOC packs, PCAP files, and other analysis artifacts
  Endpoint   : GET /falconx/entities/artifacts/v1
  Permission : falconx-sandbox:read

  -ArtifactId [String] <Required>
    Artifact identifier

  -Path [String] <Required>
    Destination Path

```
### Receive-FalconSample
```
Retrieves the file associated with the given ID (SHA256)
  Endpoint   : GET /samples/entities/samples/v2
  Permission : falconx-sandbox:read

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256 [String] <Required>
    SHA256 hash value of the target file
      Pattern : \w{64}

  -PasswordProtected [String]
    Flag whether the sample should be zipped and password protected with pass='infected'

```
### Remove-FalconReport
```
Delete sandbox reports
  Endpoint   : DELETE /falconx/entities/reports/v1
  Permission : falconx-sandbox:write

  -ReportId [String] <Required>
    Sandbox report identifier

```
### Remove-FalconSample
```
Removes a sample, including file, meta and submissions from the collection
  Endpoint   : DELETE /samples/entities/samples/v2
  Permission : falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -FileId [String] <Required>
    SHA256 hash value of the file

```
### Send-FalconSample
```
Upload a file to add to a sandbox submission
  Endpoint   : POST /samples/entities/samples/v2
  Permission : falconx-sandbox:write

  -UserUuid [String]
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Path [String] <Required>
    Path to the file
      Pattern : \.(acm|apk|ax|axf|bin|chm|cpl|dll|doc|docx|drv|efi|elf|eml|exe|hta|jar|js|ko|lnk|o|ocx|mod|msg|mui|pdf|pl|ppt|pps|pptx|ppsx|prx|ps1|psd1|psm1|pub|puff|py|rtf|scr|sct|so|svg|svr|swf|sys|tsp|vbe|vbs|wsf|xls|xlsx)+$

  -FileName [String]
    Filename

  -Comment [String]
    A comment to identify for other users to identify this sample

  -IsConfidential [Boolean]
    Defines visibility of the sample in Falcon MalQuery [$true (default): File is only shown to users within your account, $false: File can be seen by other CrowdStrike customers]

```
## /firewall-management/

### Edit-FalconFirewallGroup
```
Update name, description, or enabled status of a rule group, or create, edit, delete, or reorder rules
  Endpoint   : PATCH /fwmgr/entities/rule-groups/v1
  Permission : firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Comment [String]
    Audit log comment for this action

  -DiffOperations [Array]
    

  -DiffType [String]
    

  -GroupId [String]
    

  -RuleIds [Array]
    

  -RuleVersions [Array]
    

  -Tracking [String]
    

```
### Edit-FalconFirewallSetting
```
Update an identified policy container
  Endpoint   : PUT /fwmgr/entities/policies/v1
  Permission : firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -DefaultInbound [String]
    

  -DefaultOutbound [String]
    

  -Enforce [Boolean]
    

  -IsDefaultPolicy [Boolean]
    

  -PlatformId [String] <Required>
    

  -PolicyId [String] <Required>
    

  -RuleGroupIds [Array] <Required>
    

  -TestMode [Boolean]
    

  -Tracking [String]
    

```
### Get-FalconFirewallEvent
```
Find all event IDs matching the query with filter
  Endpoint   : GET /fwmgr/queries/events/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Match query criteria, which includes all the filter string fields, plus TODO

  -Offset [String]
    The position to begin retrieving results

  -After [String]
    A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results.

  -Limit [Int32]
    Maximum number of results

List Firewall Management events
  Endpoint   : GET /fwmgr/entities/events/v1
  Permission : firewall-management:read

  -EventIds [Array] <Required>
    The events to retrieve, identified by ID
      Pattern : [\w-]{20}

```
### Get-FalconFirewallField
```
Get the firewall field specification IDs for the provided platform
  Endpoint   : GET /fwmgr/queries/firewall-fields/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -PlatformId [String]
    Get fields configuration for this platform

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

List detailed information about Firewall Management fields
  Endpoint   : GET /fwmgr/entities/firewall-fields/v1
  Permission : firewall-management:read

  -FieldIds [Array] <Required>
    The field identifiers to retrieve

```
### Get-FalconFirewallGroup
```
Find all rule group IDs matching the query with filter
  Endpoint   : GET /fwmgr/queries/rule-groups/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Match query criteria, which includes all the filter string fields, plus TODO

  -Offset [String]
    The position to begin retrieving results

  -After [String]
    A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results.

  -Limit [Int32]
    Maximum number of results

Get rule group entities by ID. These groups do not contain their rule entites, just the rule IDs in precedence order.
  Endpoint   : GET /fwmgr/entities/rule-groups/v1
  Permission : firewall-management:read

  -GroupIds [Array] <Required>
    The IDs of the rule groups to retrieve

```
### Get-FalconFirewallPlatform
```
Get the list of platform names
  Endpoint   : GET /fwmgr/queries/platforms/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

Get platforms by ID, e.g., windows or mac or droid
  Endpoint   : GET /fwmgr/entities/platforms/v1
  Permission : firewall-management:read

  -PlatformIds [Array] <Required>
    The IDs of the platforms to retrieve

```
### Get-FalconFirewallRule
```
Find all rule IDs matching the query with filter
  Endpoint   : GET /fwmgr/queries/rules/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Match query criteria, which includes all the filter string fields, plus TODO

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

  -After [String]
    A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results.

Find all firewall rule IDs matching the query with filter, and return them in precedence order
  Endpoint   : GET /fwmgr/queries/policy-rules/v1
  Permission : firewall-management:read

  -Detailed [SwitchParameter]
    

  -PolicyId [String] <Required>
    The ID of the policy container within which to query

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Match query criteria, which includes all the filter string fields, plus TODO

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

Get rule entities by ID (64-bit unsigned int as decimal string) or Family ID (32-character hexadecimal string)
  Endpoint   : GET /fwmgr/entities/rules/v1
  Permission : firewall-management:read

  -RuleIds [Array] <Required>
    The rules to retrieve, identified by ID

```
### Get-FalconFirewallSetting
```
Get policy container entities by policy ID
  Endpoint   : GET /fwmgr/entities/policies/v1
  Permission : firewall-management:read

  -PolicyIds [Array] <Required>
    The policy container(s) to retrieve, identified by policy ID
      Pattern : \w{32}

```
### New-FalconFirewallGroup
```
Create new rule group on a platform for a customer with a name and description, and return the ID
  Endpoint   : POST /fwmgr/entities/rule-groups/v1
  Permission : firewall-management:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -CloneId [String]
    Copy settings from an existing policy
      Pattern : \w{32}

  -Library [String]
    If this flag is set to true then the rules will be cloned from the clone_id from the CrowdStrike Firewal Rule Groups Library.

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
Delete Firewall Rule Groups
  Endpoint   : DELETE /fwmgr/entities/rule-groups/v1
  Permission : firewall-management:write

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
Update Firewall Policies by specifying the ID of the policy and details to update
  Endpoint   : PATCH /policy/entities/firewall/v1
  Permission : firewall-management:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to update using a single request

```
### Get-FalconFirewallPolicy
```
Search for Firewall Policies in your environment by providing an FQL filter and paging details. Returns a set of Firewall Policy IDs which match the filter criteria
  Endpoint   : GET /policy/queries/firewall/v1
  Permission : firewall-management:read

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria
  Endpoint   : GET /policy/queries/firewall-members/v1
  Permission : firewall-management:read

  -Members [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

  -PolicyId [String]
    The ID of the Firewall Policy to search for members of

List detailed information about Firewall Policies
  Endpoint   : GET /policy/entities/firewall/v1
  Permission : firewall-management:read

  -PolicyIds [Array] <Required>
    The IDs of the Firewall Policies to return

```
### Invoke-FalconFirewallPolicyAction
```
Perform actions on Firewall Policies
  Endpoint   : POST /policy/entities/firewall-actions/v1
  Permission : firewall-management:write

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
Create Firewall Policies
  Endpoint   : POST /policy/entities/firewall/v1
  Permission : firewall-management:write

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


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to create using a single request

```
### Remove-FalconFirewallPolicy
```
Delete Firewall policies
  Endpoint   : DELETE /policy/entities/firewall/v1
  Permission : firewall-management:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}

```
### Set-FalconFirewallPrecedence
```
Sets the precedence of Firewall Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
  Endpoint   : POST /policy/entities/firewall-precedence/v1
  Permission : firewall-management:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

```
## /host-group/

### Edit-FalconHostGroup
```
Update Host Groups by specifying the ID of the group and details to update
  Endpoint   : PATCH /devices/entities/host-groups/v1
  Permission : host-group:write

  -AssignmentRule [String]
    The new assignment rule of the group. Note: If the group type is static, this field cannot be updated manually

  -Description [String]
    The new description of the group

  -GroupId [String] <Required>
    The id of the group to update
      Pattern : \w{32}

  -Name [String]
    The new name of the group


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple groups to update in a single request

```
### Get-FalconHostGroup
```
Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of Host Group IDs which match the filter criteria
  Endpoint   : GET /devices/queries/host-groups/v1
  Permission : host-group:read

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria
  Endpoint   : GET /devices/queries/host-group-members/v1
  Permission : host-group:read

  -Members [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -GroupId [String] <Required>
    The ID of the Host Group to search for members of
      Pattern : \w{32}
      Minimum : 32
      Maximum : 32

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

List detailed information about Host Groups
  Endpoint   : GET /devices/entities/host-groups/v1
  Permission : host-group:read

  -GroupIds [Array] <Required>
    The IDs of the Host Groups to return
      Pattern : \w{32}

```
### Invoke-FalconHostGroupAction
```
Perform the specified action on the Host Groups specified in the request
  Endpoint   : POST /devices/entities/host-group-actions/v1
  Permission : host-group:write

  -ActionName [String] <Required>
    The action to perform on the target Host Groups
      Accepted : add-hosts, remove-hosts

  -GroupId [String] <Required>
    Host group identifier
      Pattern : \w{32}
      Minimum : 32
      Maximum : 32

  -FilterName [String] <Required>
    FQL filter name
      Accepted : device_id, domain, external_ip, groups, hostname, local_ip, mac_address, os_version, ou, platform_name, site, system_manufacturer

  -FilterValue [Array] <Required>
    One or more values for use with the FQL filter

```
### New-FalconHostGroup
```
Create Host Groups
  Endpoint   : POST /devices/entities/host-groups/v1
  Permission : host-group:write

  -AssignmentRule [String]
    An FQL filter expression to dynamically assign hosts

  -Description [String]
    Group description

  -GroupType [String] <Required>
    Group type
      Accepted : static, dynamic

  -Name [String] <Required>
    Group name


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple groups to create using a single request

```
### Remove-FalconHostGroup
```
Delete Host Groups
  Endpoint   : DELETE /devices/entities/host-groups/v1
  Permission : host-group:write

  -GroupIds [Array] <Required>
    One or more group identifiers
      Pattern : \w{32}

```
## /hosts/

### Get-FalconHost
```
Search for hosts
  Endpoint   : GET /devices/queries/devices-scroll/v1
  Permission : devices:read

  -Detailed [SwitchParameter]
    

  -All [SwitchParameter]
    

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

Retrieve hidden hosts that match the provided filter criteria.
  Endpoint   : GET /devices/queries/devices-hidden/v1
  Permission : devices:read

  -Hidden [SwitchParameter] <Required>
    Search for hidden hosts

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

List detailed Host information
  Endpoint   : GET /devices/entities/devices/v1
  Permission : devices:read

  -HostIds [Array] <Required>
    The host agentIDs used to get details on
      Pattern : \w{32}

```
### Invoke-FalconHostAction
```
Perform actions on Hosts
  Endpoint   : POST /devices/entities/devices-actions/v2
  Permission : devices:write

  -ActionName [String] <Required>
    The action to perform on the target Hosts
      Accepted : contain, lift_containment, hide_host, unhide_host

  -HostIds [Array] <Required>
    Host identifiers
      Pattern : \w{32}

```
## /incidents/

### Get-FalconBehavior
```
Search for behaviors by providing an FQL filter, sorting, and paging details
  Endpoint   : GET /incidents/queries/behaviors/v1
  Permission : incidents:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 500

  -Sort [String]
    Property and direction to sort results
      Accepted : timestamp|asc, timestamp|desc

List detailed information about behaviors
  Endpoint   : POST /incidents/entities/behaviors/GET/v1
  Permission : incidents:read

  -BehaviorIds [Array] <Required>
    One or more behavior identifiers

```
### Get-FalconIncident
```
Search for incidents by providing an FQL filter, sorting, and paging details
  Endpoint   : GET /incidents/queries/incidents/v1
  Permission : incidents:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Sort [String]
    Property and direction to sort results
      Accepted : assigned_to|asc, assigned_to|desc, assigned_to_name|asc, assigned_to_name|desc, end|asc, end|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, sort_score|asc, sort_score|desc, start|asc, start|desc, state|asc, state|desc, status|asc, status|desc

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 500

List detailed information about Incidents
  Endpoint   : POST /incidents/entities/incidents/GET/v1
  Permission : incidents:read

  -IncidentIds [Array] <Required>
    

```
### Get-FalconScore
```
List CrowdScore values
  Endpoint   : GET /incidents/combined/crowdscores/v1
  Permission : incidents:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 2500

  -Sort [String]
    Property and direction to sort results
      Accepted : score|asc, score|desc, timestamp|asc, timestamp|desc

```
### Invoke-FalconIncidentAction
```
Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description
  Endpoint   : POST /incidents/entities/incident-actions/v1
  Permission : incidents:write

  -ActionName [String] <Required>
    Action to perform
      Accepted : add_tag, delete_tag, update_description, update_name, update_status

  -ActionValue [String] <Required>
    Value for the chosen action

  -IncidentIds [Array] <Required>
    Incident identifiers
      Pattern : inc:\w{32}:\w{32}

  -UpdateDetects [Boolean]
    Update the status of 'new' related detections

  -OverwriteDetects [String]
    Replace existing status for related detections

```
## /installation-tokens/

### Edit-FalconInstallToken
```
Updates one or more tokens. Use this endpoint to edit labels, change expiration, revoke, or restore.
  Endpoint   : PATCH /installation-tokens/entities/tokens/v1
  Permission : installation-tokens:write

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
Search for tokens by providing an FQL filter and paging details.
  Endpoint   : GET /installation-tokens/queries/tokens/v1
  Permission : installation-tokens:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 1000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

Gets the details of one or more tokens by id.
  Endpoint   : GET /installation-tokens/entities/tokens/v1
  Permission : installation-tokens:read

  -TokenIds [Array]
    One or more token identifiers
      Pattern : \w{32}

```
### Get-FalconTokenEvent
```
Search for installation token audit events
  Endpoint   : GET /installation-tokens/queries/audit-events/v1
  Permission : installation-tokens:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 1000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

Retrieve installation token audit events
  Endpoint   : GET /installation-tokens/entities/audit-events/v1
  Permission : installation-tokens:read

  -EventIds [Array]
    One or more event identifiers

```
### Get-FalconTokenSettings
```
List installation token settings
  Endpoint   : GET /installation-tokens/entities/customer-settings/v1
  Permission : installation-tokens:read

```
### New-FalconInstallToken
```
Creates a token.
  Endpoint   : POST /installation-tokens/entities/tokens/v1
  Permission : installation-tokens:write

  -ExpiresTimestamp [String]
    The token's expiration time (RFC-3339). Null, if the token never expires.

  -Label [String]
    The token label.

```
### Remove-FalconInstallToken
```
Deletes a token immediately. To revoke a token, use PATCH /installation-tokens/entities/tokens/v1 instead.
  Endpoint   : DELETE /installation-tokens/entities/tokens/v1
  Permission : installation-tokens:write

  -TokenIds [Array] <Required>
    One or more token identifiers
      Pattern : \w{32}

```
## /intel/

### Get-FalconActor
```
Get actor IDs that match provided FQL filters.
  Endpoint   : GET /intel/queries/actors/v1
  Permission : falconx-actors:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Perform a generic substring search across all fields.

List detailed information about Actors
  Endpoint   : GET /intel/entities/actors/v1
  Permission : falconx-actors:read

  -ActorIds [Array] <Required>
    The IDs of the actors you want to retrieve.

  -Fields [Array]
    The fields to return, or a predefined collection name surrounded by two underscores

```
### Get-FalconIndicator
```
Get indicators IDs that match provided FQL filters.
  Endpoint   : GET /intel/queries/indicators/v1
  Permission : falconx-indicators:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 50000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Perform a generic substring search across all fields.

  -IncludeDeleted [Boolean]
    Include both published and deleted indicators

List detailed information about Indicators
  Endpoint   : POST /intel/entities/indicators/GET/v1
  Permission : falconx-indicators:read

  -IndicatorIds [Array] <Required>
    

```
### Get-FalconIntel
```
Get report IDs that match provided FQL filters.
  Endpoint   : GET /intel/queries/reports/v1
  Permission : falconx-reports:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

  -Query [String]
    Perform a generic substring search across all fields.

List detailed information about Intel Reports
  Endpoint   : GET /intel/entities/reports/v1
  Permission : falconx-reports:read

  -ReportIds [Array] <Required>
    The IDs of the reports you want to retrieve.

  -Fields [Array]
    The fields to return, or a predefined collection name surrounded by two underscores

```
### Get-FalconRule
```
Search for rule IDs that match provided filter criteria.
  Endpoint   : GET /intel/queries/rules/v1
  Permission : falconx-rules:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

  -Sort [String]
    Property and direction to sort results

  -Name [Array]
    Search by rule title.

  -Type [String] <Required>
    The rule news report type. Accepted values:

snort-suricata-master

snort-suricata-update

snort-suricata-changelog

yara-master

yara-update

yara-changelog

common-event-format

netwitness
      Accepted : snort-suricata-master, snort-suricata-update, snort-suricata-changelog, yara-master, yara-update, yara-changelog, common-event-format, netwitness

  -Description [Array]
    Substring match on description field.

  -Tags [Array]
    Search for rule tags.

  -MinCreatedDate [Int32]
    Filter results to those created on or after a certain date.

  -MaxCreatedDate [String]
    Filter results to those created on or before a certain date.

  -Query [String]
    Perform a generic substring search across all fields.

List detailed information about Intel Rules
  Endpoint   : GET /intel/entities/rules/v1
  Permission : falconx-rules:read

  -RuleIds [Array] <Required>
    The ids of rules to return.

```
### Receive-FalconIntel
```
Download an Intel Report PDF
  Endpoint   : GET /intel/entities/report-files/v1
  Permission : falconx-reports:read

  -ReportId [String] <Required>
    The ID of the report you want to download as a PDF.

  -Path [String] <Required>
    Destination Path
      Pattern : \.pdf$

```
### Receive-FalconRule
```
Download a specific threat intelligence ruleset zip file
  Endpoint   : GET /intel/entities/rules-files/v1
  Permission : falconx-rules:read

  -RuleId [Int32] <Required>
    Rule set identifier

  -Path [String] <Required>
    Destination Path
      Pattern : \.zip$

Download the latest threat intelligence ruleset zip file
  Endpoint   : GET /intel/entities/rules-latest-files/v1
  Permission : falconx-rules:read

  -Path [String] <Required>
    Destination Path
      Pattern : \.zip$

  -Type [String] <Required>
    Rule news report type
      Accepted : snort-suricata-master, snort-suricata-update, snort-suricata-changelog, yara-master, yara-update, yara-changelog, common-event-format, netwitness

```
## /iocs/

### Edit-FalconIOC
```
Update a custom IOC
  Endpoint   : PATCH /indicators/entities/iocs/v1
  Permission : iocs:write

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
      Minimum : 1
      Maximum : 200

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

  -Description [String]
    Custom IOC description

```
### Get-FalconIOC
```
Search the custom IOCs in your customer account
  Endpoint   : GET /indicators/queries/iocs/v1
  Permission : iocs:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Type [String]
    Type of indicator
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String]
    The string representation of the indicator
      Minimum : 1
      Maximum : 200

  -Offset [String]
    Position to begin retrieving results

  -FromExpirationTimestamp [String]
    Find custom IOCs created after this time (RFC-3339 timestamp)

  -ToExpirationTimestamp [String]
    Find custom IOCs created before this time (RFC-3339 timestamp)

  -Policy [String]
    Custom IOC policy type ['detect', 'none']
      Accepted : detect, none

  -Sources [String]
    The source where this indicator originated. This can be used for tracking where this indicator was defined.
      Minimum : 1
      Maximum : 200

  -ShareLevels [String]
    The level at which the indicator will be shared. Currently only red share level (not shared) is supported, indicating that the IOC isn't shared with other FH customers.
      Accepted : red

  -CreatedBy [String]
    The user or API client who created the Custom IOC

  -DeletedBy [String]
    The user or API client who deleted the Custom IOC

  -IncludeDeleted [Boolean]
    Include deleted IOCs 

List the number of hosts that have observed a custom IOC
  Endpoint   : GET /indicators/aggregates/devices-count/v1
  Permission : iocs:read

  -Count [SwitchParameter] <Required>
    

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

List the host identifiers that have observed a custom IOC
  Endpoint   : GET /indicators/queries/devices/v1
  Permission : iocs:read

  -Hosts [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 100

  -Offset [String]
    The position to begin retrieving results

Search for processes associated with a custom IOC
  Endpoint   : GET /indicators/queries/processes/v1
  Permission : iocs:read

  -Processes [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 100

  -Offset [String]
    The position to begin retrieving results

  -HostId [String] <Required>
    Target Host identifier
      Pattern : \w{32}

Get detailed information about an IOC
  Endpoint   : GET /indicators/entities/iocs/v1
  Permission : iocs:read

  -Type [String] <Required>
    Indicator type ['sha256', 'md5', 'domain', 'ipv4', 'ipv6']
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Indicator value
      Minimum : 1
      Maximum : 200

```
### Get-FalconProcess
```
Search for processes associated with a custom IOC
  Endpoint   : GET /indicators/queries/processes/v1
  Permission : iocs:read

Retrieve detail about a process
  Endpoint   : GET /processes/entities/processes/v1
  Permission : iocs:read

  -ProcessIds [Array] <Required>
    One or more process identifiers

```
### New-FalconIOC
```
Create custom IOCs
  Endpoint   : POST /indicators/entities/iocs/v1
  Permission : iocs:write

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
      Minimum : 1
      Maximum : 200

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

Create up to 200 custom IOCs in a single request
  Endpoint   : POST /indicators/entities/iocs/v1
  Permission : iocs:write

  -Array [Array] <Required>
    One or more hashtables of custom IOCs

```
### Remove-FalconIOC
```
Delete a custom IOC
  Endpoint   : DELETE /indicators/entities/iocs/v1
  Permission : iocs:write

  -Type [String] <Required>
    Custom IOC type
      Accepted : sha256, md5, domain, ipv4, ipv6

  -Value [String] <Required>
    Custom IOC value
      Minimum : 1
      Maximum : 200

```
### Show-FalconMap
```
Graph Indicators
  Endpoint   : POST /intelligence/graph?indicators=
  Permission : 

  -Indicators [Array] <Required>
    Indicators to graph
      Pattern : (sha256|md5|domain|ipv4|ipv6):.*

```
## /malquery/

### Get-FalconMalQuery
```
Check the status and results of a MalQuery request
  Endpoint   : GET /malquery/entities/requests/v1
  Permission : malquery:read

  -QueryIds [Array] <Required>
    MalQuery request identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```
### Get-FalconMalQueryFile
```
Retrieve indexed files metadata by their hash
  Endpoint   : GET /malquery/entities/metadata/v1
  Permission : malquery:read

  -FileIds [Array] <Required>
    The file SHA256.

```
### Get-FalconQuota
```
Get information about search and download quotas in your environment
  Endpoint   : GET /malquery/aggregates/quotas/v1
  Permission : malquery:read

```
### Invoke-FalconMalQuery
```
Search MalQuery for a combination of hex patterns and strings
  Endpoint   : POST /malquery/queries/exact-search/v1
  Permission : malquery:write

  -FilterFileTypes [Array]
    File types to include with the results
      Pattern : (cdf|cdfv2|cjava|dalvik|doc|docx|elf32|elf64|email|html|hwp|java.arc|lnk|macho|pcap|pdf|pe32|pe64|perl|ppt|pptx|python|pythonc|rtf|swf|text|xls|xlsx)

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results

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

Search MalQuery quickly, but with more potential for false positives.
  Endpoint   : POST /malquery/combined/fuzzy-search/v1
  Permission : malquery:write

  -Fuzzy [SwitchParameter] <Required>
    

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results

  -PatternType [String] <Required>
    Pattern type
      Accepted : hex, ascii, wide

  -PatternValue [String] <Required>
    Pattern value

Schedule a YARA-based search for execution
  Endpoint   : POST /malquery/queries/hunt/v1
  Permission : malquery:write

  -Hunt [SwitchParameter] <Required>
    

  -FilterFileTypes [Array]
    File types to include with the results
      Pattern : (cdf|cdfv2|cjava|dalvik|doc|docx|elf32|elf64|email|html|hwp|java.arc|lnk|macho|pcap|pdf|pe32|pe64|perl|ppt|pptx|python|pythonc|rtf|swf|text|xls|xlsx)

  -FilterMeta [Array]
    Subset of metadata fields to include in the results
      Pattern : (sha256|md5|type|size|first_seen|label|family)

  -Limit [Int32]
    Maximum number of results

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

  -YaraRule [String] <Required>
    A YARA rule that defines your search

```
### Invoke-FalconMalQueryJob
```
Schedule samples for download from MalQuery
  Endpoint   : POST /malquery/entities/samples-multidownload/v1
  Permission : malquery:write

  -SampleIds [Array] <Required>
    List of sample sha256 ids

```
### Receive-FalconMalQueryFile
```
Download a file indexed by MalQuery using its SHA256 value
  Endpoint   : GET /malquery/entities/download-files/v1
  Permission : malquery:read

  -Sha256 [String] <Required>
    SHA256 value of the sample
      Minimum : 64
      Maximum : 64

  -Path [String] <Required>
    Destination Path

Download a zip containing Malquery samples (password: infected)
  Endpoint   : GET /malquery/entities/samples-fetch/v1
  Permission : malquery:read

  -Path [String] <Required>
    Destination Path

  -JobId [String] <Required>
    Sample job identifier

```
## /oauth2/

### Request-FalconToken
```
Generate an OAuth2 access token
  Endpoint   : POST /oauth2/token
  Permission : 

  -Cloud [String]
    Destination CrowdStrike cloud
      Accepted : eu-1, us-gov-1, us-1, us-2

  -Id [String]
    The API client ID to authenticate your API requests
      Minimum : 32
      Maximum : 32

  -Secret [String]
    The API client secret to authenticate your API requests
      Minimum : 40
      Maximum : 40

  -CID [String]
    For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID
      Minimum : 32
      Maximum : 32

```
### Revoke-FalconToken
```
## /prevention-policies/

### Edit-FalconPreventionPolicy
```
Update Prevention Policies by specifying the ID of the policy and details to update
  Endpoint   : PATCH /policy/entities/prevention/v1
  Permission : prevention-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    The id of the policy to update

  -Name [String]
    The new name to assign to the policy

  -Settings [Array]
    An array of hashtables defining policy settings


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to update using a single request

```
### Get-FalconPreventionPolicy
```
Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a set of Prevention Policy IDs which match the filter criteria
  Endpoint   : GET /policy/queries/prevention/v1
  Permission : prevention-policies:read

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

Search for members of a Prevention Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria
  Endpoint   : GET /policy/queries/prevention-members/v1
  Permission : prevention-policies:read

  -Members [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

  -PolicyId [String]
    The ID of the Prevention Policy to search for members of

Retrieve a set of Prevention policies
  Endpoint   : GET /policy/entities/prevention/v1
  Permission : prevention-policies:read

  -PolicyIds [Array] <Required>
    Prevention policy identifiers

```
### Invoke-FalconPreventionPolicyAction
```
Perform actions on Prevention Policies
  Endpoint   : POST /policy/entities/prevention-actions/v1
  Permission : prevention-policies:write

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
Create Prevention Policies
  Endpoint   : POST /policy/entities/prevention/v1
  Permission : prevention-policies:write

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


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to create using a single request

```
### Remove-FalconPreventionPolicy
```
Delete Prevention policies
  Endpoint   : DELETE /policy/entities/prevention/v1
  Permission : prevention-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}

```
### Set-FalconPreventionPrecedence
```
Sets the precedence of Prevention Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
  Endpoint   : POST /policy/entities/prevention-precedence/v1
  Permission : prevention-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux
```
## /real-time-response/

### Confirm-FalconCommand
```
Get status of an executed command on a single host.
  Endpoint   : GET /real-time-response/entities/command/v1
  Permission : real-time-response:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

```
### Confirm-FalconGetFile
```
Get a list of files for the specified RTR session.
  Endpoint   : GET /real-time-response/entities/file/v1
  Permission : real-time-response:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

Retrieve the status of a 'get' command issued to a batch Real-time Response session
  Endpoint   : GET /real-time-response/combined/batch-get-command/v1
  Permission : real-time-response:write

  -All [SwitchParameter]
    

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -BatchGetCmdReqId [String] <Required>
    Batch 'get' command request identifier

```
### Confirm-FalconResponderCommand
```
Check the status of an Active Responder Real-time Response command
  Endpoint   : GET /real-time-response/entities/active-responder-command/v1
  Permission : real-time-response:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

```
### Get-FalconSession
```
Get a list of session_ids.
  Endpoint   : GET /real-time-response/queries/sessions/v1
  Permission : real-time-response:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

  -Sort [String]
    Property and direction to sort results

  -Filter [String]
    An FQL filter expression

Get queued session metadata by session ID.
  Endpoint   : POST /real-time-response/entities/queued-sessions/GET/v1
  Permission : real-time-response:read

  -Queue [SwitchParameter] <Required>
    

  -SessionIds [Array] <Required>
    One or more session identifiers

Get session metadata by session id.
  Endpoint   : POST /real-time-response/entities/sessions/GET/v1
  Permission : real-time-response:read

  -SessionIds [Array] <Required>
    One or more session identifiers

```
### Invoke-FalconBatchGet
```
Send a 'get' request to a batch Real-time Response session
  Endpoint   : POST /real-time-response/combined/batch-get-command/v1
  Permission : real-time-response:write

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

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
Issue a Real-time Response command to a session
  Endpoint   : POST /real-time-response/entities/command/v1
  Permission : real-time-response:read

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, csrutil, env, eventlog, filehash, getsid, help, history, ifconfig, ipconfig, ls, mount, netstat, ps, reg query, users

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

Issue a Real-time Response command to a batch session
  Endpoint   : POST /real-time-response/combined/batch-command/v1
  Permission : real-time-response:read

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, csrutil, env, eventlog, filehash, getsid, help, history, ifconfig, ipconfig, ls, mount, netstat, ps, reg query, users

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Arguments [String]
    Arguments to include with the command

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}

```
### Invoke-FalconResponderCommand
```
Issue a Real-time Response command to a session using Active Responder permissions
  Endpoint   : POST /real-time-response/entities/active-responder-command/v1
  Permission : real-time-response:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history, ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg delete, reg load, reg query, reg set, reg unload, restart, rm, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

Issue a Real-time Response command to a batch session using Active Responder permissions
  Endpoint   : POST /real-time-response/combined/batch-active-responder-command/v1
  Permission : real-time-response:write

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history, ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg delete, reg load, reg query, reg set, reg unload, restart, rm, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Arguments [String]
    Arguments to include with the command

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}

```
### Receive-FalconGetFile
```
Download a file extracted through a Real-time Response 'get' request
  Endpoint   : GET /real-time-response/entities/extracted-file-contents/v1
  Permission : real-time-response:write

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Sha256 [String] <Required>
    SHA256 value of the extracted file
      Minimum : 64
      Maximum : 64

  -Path [String] <Required>
    Full destination path for .7z file
      Pattern : \.7z$

```
### Remove-FalconCommand
```
Delete a queued session command
  Endpoint   : DELETE /real-time-response/entities/queued-sessions/command/v1
  Permission : real-time-response:read

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```
### Remove-FalconGetFile
```
Delete a RTR session file.
  Endpoint   : DELETE /real-time-response/entities/file/v1
  Permission : real-time-response:write

  -FileId [String] <Required>
    File identifier

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```
### Remove-FalconSession
```
Delete a session.
  Endpoint   : DELETE /real-time-response/entities/sessions/v1
  Permission : real-time-response:read

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```
### Start-FalconSession
```
Initialize a Real-time Response session
  Endpoint   : POST /real-time-response/entities/sessions/v1
  Permission : real-time-response:read

  -QueueOffline [Boolean]
    Add this session to the offline queue if the host does not initialize

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}
      Minimum : 32
      Maximum : 32

  -Origin [String]
    Optional comment about the creation of the session

Initialize a Real-time Response session on multiple hosts
  Endpoint   : POST /real-time-response/combined/batch-init-session/v1
  Permission : real-time-response:read

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -ExistingBatchId [String]
    Add hosts to an existing batch session
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -HostIds [Array] <Required>
    Host identifiers
      Pattern : \w{32}

  -QueueOffline [Boolean]
    Add sessions in this batch to the offline queue if the hosts do not initialize

```
### Update-FalconSession
```
Refresh a session timeout on a single host.
  Endpoint   : POST /real-time-response/entities/refresh-session/v1
  Permission : real-time-response:read

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}
      Minimum : 32
      Maximum : 32

  -QueueOffline [Boolean]
    Add session to the offline queue

Refresh a batch Real-time Response session, to avoid hitting the default timeout of 10 minutes
  Endpoint   : POST /real-time-response/combined/batch-refresh-session/v1
  Permission : real-time-response:read

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RemoveHostIds [Array]
    Host identifiers to remove from the batch session
      Pattern : \w{32}

```
## /real-time-response-admin/

### Confirm-FalconAdminCommand
```
Get status of an executed RTR administrator command on a single host.
  Endpoint   : GET /real-time-response/entities/admin-command/v1
  Permission : real-time-response-admin:write

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -CloudRequestId [String] <Required>
    Cloud request identifier of the executed command
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -SequenceId [Int32]
    Sequence identifier [default: 0]

```
### Get-FalconPutFile
```
Get a list of put-file ID's that are available to the user for the `put` command.
  Endpoint   : GET /real-time-response/queries/put-files/v1
  Permission : real-time-response-admin:write

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

  -Sort [String]
    Property and direction to sort results

Get put-files based on the ID's given. These are used for the RTR `put` command.
  Endpoint   : GET /real-time-response/entities/put-files/v1
  Permission : real-time-response-admin:write

  -FileIds [Array] <Required>
    One or more file identifiers

```
### Get-FalconScript
```
Get a list of custom-script ID's that are available to the user for the `runscript` command.
  Endpoint   : GET /real-time-response/queries/scripts/v1
  Permission : real-time-response-admin:write

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Filter [String]
    An FQL filter expression

  -Offset [String]
    The position to begin retrieving results

  -Limit [Int32]
    Maximum number of results

  -Sort [String]
    Property and direction to sort results

Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command.
  Endpoint   : GET /real-time-response/entities/scripts/v1
  Permission : real-time-response-admin:write

  -ScriptIds [Array] <Required>
    One or more script identifiers

```
### Invoke-FalconAdminCommand
```
Issue a Real-time Response command to a session using Admin permissions
  Endpoint   : POST /real-time-response/entities/admin-command/v1
  Permission : real-time-response-admin:write

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history, ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg delete, reg load, reg query, reg set, reg unload, restart, rm, run, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -Arguments [String]
    Arguments to include with the command

  -SessionId [String] <Required>
    Real-time Response session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

Issue a Real-time Response command to a batch session using Admin permissions
  Endpoint   : POST /real-time-response/combined/batch-admin-command/v1
  Permission : real-time-response-admin:write

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -Command [String] <Required>
    Command to issue
      Accepted : cat, cd, clear, cp, csrutil, encrypt, env, eventlog, filehash, get, getsid, help, history, ifconfig, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg delete, reg load, reg query, reg set, reg unload, restart, rm, run, runscript, shutdown, umount, unmap, users, xmemdump, zip

  -BatchId [String] <Required>
    Real-time Response batch session identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -Arguments [String]
    Arguments to include with the command

  -OptionalHostIds [Array]
    Restrict the request to specific host identifiers
      Pattern : \w{32}

```
### Invoke-FalconForensics
```
Deploy and execute Falcon Forensics using Real-time Response
  Endpoint   :  
  Permission : real-time-response:read, real-time-response-admin:write

  -Path [String] <Required>
    Path to the Falcon Forensics executable

  -HostIds [Array] <Required>
    Host identifiers
      Pattern : \w{32}

  -Timeout [Int32]
    Length of time to wait for a result, in seconds
      Minimum : 30
      Maximum : 600

  -QueueOffline [Boolean]
    Add this session to the offline queue if the host does not initialize

```
### Remove-FalconPutFile
```
Delete a put-file based on the ID given.  Can only delete one file at a time.
  Endpoint   : DELETE /real-time-response/entities/put-files/v1
  Permission : real-time-response-admin:write

  -FileId [String] <Required>
    File identifier

```
### Remove-FalconScript
```
Delete a custom-script based on the ID given.  Can only delete one script at a time.
  Endpoint   : DELETE /real-time-response/entities/scripts/v1
  Permission : real-time-response-admin:write

  -FileId [String] <Required>
    Script identifier

```
### Send-FalconPutFile
```
Upload a new put-file to use for the RTR `put` command.
  Endpoint   : POST /real-time-response/entities/put-files/v1
  Permission : real-time-response-admin:write

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
Upload a new custom-script to use for the RTR `runscript` command.
  Endpoint   : POST /real-time-response/entities/scripts/v1
  Permission : real-time-response-admin:write

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
## /sensor-download/

### Get-FalconCCID
```
Get CCID to use with sensor installers
  Endpoint   : GET /sensors/queries/installers/ccid/v1
  Permission : sensor-installers:read

```
### Get-FalconInstaller
```
Get sensor installer IDs by provided query
  Endpoint   : GET /sensors/queries/installers/v1
  Permission : sensor-installers:read

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 500

  -Sort [String]
    Property and direction to sort results
      Accepted : release_date|asc, release_date|desc, version|asc, version|desc

  -Filter [String]
    An FQL filter expression

Get sensor installer details by provided SHA256 IDs
  Endpoint   : GET /sensors/entities/installers/v1
  Permission : sensor-installers:read

  -FileIds [Array] <Required>
    The IDs of the installers

```
### Receive-FalconInstaller
```
Download a sensor installer
  Endpoint   : GET /sensors/entities/download-installer/v1
  Permission : sensor-installers:read

  -InstallerId [String] <Required>
    SHA256 hash value of the installer to download
      Pattern : \w{64}
      Minimum : 64
      Maximum : 64

  -Path [String] <Required>
    Destination path
      Pattern : \.(deb|exe|html|pkg|rpm)+$

```
## /sensor-update-policies/

### Edit-FalconSensorUpdatePolicy
```
Update Sensor Update Policies by specifying the ID of the policy and details to update
  Endpoint   : PATCH /policy/entities/sensor-update/v2
  Permission : sensor-update-policies:write

  -Description [String]
    The new description to assign to the policy

  -PolicyId [String] <Required>
    Policy identifier
      Pattern : \w{32}

  -Name [String]
    The new name to assign to the policy

  -Settings [Hashtable]
    A hashtable defining policy settings


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to update using a single request

```
### Get-FalconBuild
```
Retrieve available builds for use with Sensor Update Policies
  Endpoint   : GET /policy/combined/sensor-update-builds/v1
  Permission : sensor-update-policies:read

  -Platform [String]
    The platform to return builds for
      Accepted : linux, mac, windows

```
### Get-FalconSensorUpdatePolicy
```
Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policy IDs which match the filter criteria
  Endpoint   : GET /policy/queries/sensor-update/v1
  Permission : sensor-update-policies:read

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria
  Endpoint   : GET /policy/queries/sensor-update-members/v1
  Permission : sensor-update-policies:read

  -Members [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

  -PolicyId [String]
    The ID of the Sensor Update Policy to search for members of
      Pattern : \w{32}

Search for Sensor Update Policies with additional support for uninstall protection in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter criteria
  Endpoint   : GET /policy/combined/sensor-update/v2
  Permission : sensor-update-policies:read

  -Detailed [SwitchParameter] <Required>
    

  -All [SwitchParameter]
    

  -Filter [String]
    An FQL filter expression

  -Offset [Int32]
    Position to begin retrieving results

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 5000

  -Sort [String]
    Property and direction to sort results
      Accepted : created_by|asc, created_by|desc, created_timestamp|asc, created_timestamp|desc, enabled|asc, enabled|desc, modified_by|asc, modified_by|desc, modified_timestamp|asc, modified_timestamp|desc, name|asc, name|desc, platform_name|asc, platform_name|desc, precedence|asc, precedence|desc

Retrieve a set of Sensor Update Policies with additional support for uninstall protection by specifying their IDs
  Endpoint   : GET /policy/entities/sensor-update/v2
  Permission : sensor-update-policies:read

  -PolicyIds [Array] <Required>
    The IDs of the Sensor Update Policies to return

```
### Get-FalconUninstallToken
```
Reveal an uninstall token for a specific device, or use 'MAINTENANCE' to reveal the bulk token
  Endpoint   : POST /policy/combined/reveal-uninstall-token/v1
  Permission : sensor-update-policies:write

  -AuditMessage [String]
    A comment to append to the audit log

  -HostId [String] <Required>
    Host identifier
      Pattern : \w{32}
      Minimum : 32
      Maximum : 32

```
### Invoke-FalconSensorUpdatePolicyAction
```
Perform actions on Sensor Update Policies
  Endpoint   : POST /policy/entities/sensor-update-actions/v1
  Permission : sensor-update-policies:write

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
Create Sensor Update Policies
  Endpoint   : POST /policy/entities/sensor-update/v2
  Permission : sensor-update-policies:write

  -Description [String]
    The description to use when creating the policy

  -Name [String] <Required>
    The name to use when creating the policy

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

  -Settings [Hashtable]
    A hashtable defining policy settings


  Endpoint   :  
  Permission : 

  -Array [Array] <Required>
    An array containing multiple policies to create using a single request

```
### Remove-FalconSensorUpdatePolicy
```
Delete Sensor Update policies
  Endpoint   : DELETE /policy/entities/sensor-update/v1
  Permission : sensor-update-policies:write

  -PolicyIds [Array] <Required>
    One or more policy identifiers
      Pattern : \w{32}

```
### Set-FalconSensorUpdatePrecedence
```
Sets the precedence of Sensor Update Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
  Endpoint   : POST /policy/entities/sensor-update-precedence/v1
  Permission : sensor-update-policies:write

  -PolicyIds [Array] <Required>
    All of the policy identifiers for the specified platform

  -PlatformName [String] <Required>
    Platform name
      Accepted : Windows, Mac, Linux

```
## /spotlight-vulnerabilities/

### Get-FalconRemediation
```
Get information about remediations
  Endpoint   : GET /spotlight/entities/remediations/v2
  Permission : spotlight-vulnerabilities:read

  -RemediationIds [Array] <Required>
    Remediation identifiers
      Pattern : \w{32}

```
### Get-FalconVulnerability
```
Search for vulnerability identifiers
  Endpoint   : GET /spotlight/queries/vulnerabilities/v1
  Permission : spotlight-vulnerabilities:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

  -After [String]
    A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results.

  -Limit [Int32]
    Maximum number of results
      Minimum : 1
      Maximum : 400

  -Sort [String]
    Property and direction to sort results
      Accepted : closed_timestamp|asc, closed_timestamp|desc, created_timestamp|asc, created_timestamp|desc

  -Filter [String]
    An FQL filter expression

Get details on vulnerabilities by providing one or more IDs
  Endpoint   : GET /spotlight/entities/vulnerabilities/v2
  Permission : spotlight-vulnerabilities:read

  -VulnerabilityIds [Array] <Required>
    One or more vulnerability IDs. Find vulnerability IDs with GET /spotlight/queries/vulnerabilities/v2

```
## /user-management/

### Add-FalconRole
```
Assign one or more roles to a user
  Endpoint   : POST /user-roles/entities/user-roles/v1
  Permission : usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RoleIds [Array] <Required>
    One or more roles to assign

```
### Edit-FalconUser
```
Modify an existing user's first or last name
  Endpoint   : PATCH /users/entities/users/v1
  Permission : usermgmt:write

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
List user role identifiers
  Endpoint   : GET /user-roles/queries/user-role-ids-by-cid/v1
  Permission : usermgmt:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

Get info about a role
  Endpoint   : GET /user-roles/entities/user-roles/v1
  Permission : usermgmt:read

  -RoleIds [Array] <Required>
    ID of a role. Find a role ID from `/customer/queries/roles/v1` or `/users/queries/roles/v1`.

Show role IDs of roles assigned to a user. For more information on each role, provide the role ID to `/customer/entities/roles/v1`.
  Endpoint   : GET /user-roles/queries/user-role-ids-by-user-uuid/v1
  Permission : usermgmt:read

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```
### Get-FalconUser
```
List all user identifiers
  Endpoint   : GET /users/queries/user-uuids-by-cid/v1
  Permission : usermgmt:read

  -Detailed [SwitchParameter]
    Retrieve detailed information

  -All [SwitchParameter]
    Repeat requests until all available results are retrieved

List all usernames (typically an email address)
  Endpoint   : GET /users/queries/emails-by-cid/v1
  Permission : usermgmt:read

  -Names [SwitchParameter] <Required>
    

Get detailed information about a user
  Endpoint   : GET /users/entities/users/v1
  Permission : usermgmt:read

  -UserIds [Array] <Required>
    One or more user identifiers
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

Retrieve a user identifier by providing a username (typically an email address)
  Endpoint   : GET /users/queries/user-uuids-by-email/v1
  Permission : usermgmt:read

  -Username [Array] <Required>
    Email address or username

```
### New-FalconUser
```
Create a user
  Endpoint   : POST /users/entities/users/v1
  Permission : usermgmt:write

  -FirstName [String]
    User's first name

  -LastName [String]
    User's last name

  -Password [String]
    The user's password. If left blank, the system will generate an email asking them to set their password (recommended)

  -Username [String] <Required>
    A username; typically an email address

```
### Remove-FalconRole
```
Revoke one or more roles from a user
  Endpoint   : DELETE /user-roles/entities/user-roles/v1
  Permission : usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

  -RoleIds [Array] <Required>
    One or more roles

```
### Remove-FalconUser
```
Delete a user
  Endpoint   : DELETE /users/entities/users/v1
  Permission : usermgmt:write

  -UserUuid [String] <Required>
    User identifier
      Pattern : \w{8}-\w{4}-\w{4}-\w{4}-\w{12}

```