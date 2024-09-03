#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}

<#
.SYNOPSIS
Retrieve and report exclusions configured in CrowdStrike Falcon.
.DESCRIPTION
This script retrieves the ML exclusions, IOA exclusions, and Sensor Visibility exclusions configured in CrowdStrike Falcon and outputs the results.
.PARAMETER ClientId
OAuth2 client identifier.
.PARAMETER ClientSecret
OAuth2 client secret.
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1'].
.PARAMETER Hostname
CrowdStrike API hostname.
.PARAMETER OutputFormat
Specifies the format of the output. Allowed values are 'CSV', 'Text', and 'JSON'.
.NOTES
Ensure you have the necessary permissions to access this information and the PSFalcon module installed.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,

    [Parameter(Mandatory=$true)]
    [ValidateSet('CSV', 'Text', 'JSON')]
    [string]$OutputFormat,

    [Parameter(ValueFromPipelineByPropertyName, Position=3)]
    [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
    [string]$Cloud = 'us-1',

    [Parameter(ValueFromPipelineByPropertyName, Position=4)]
    [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
    [string]$Hostname
)

# Define the fields to be included in the output for each exclusion type
[string[]]$MlFields = 'id', 'value', 'regexp_value', 'value_hash', 'excluded_from', 'groups', 'applied_globally', 'last_modified', 'modified_by', 'created_on', 'created_by'
[string[]]$IoaFields = 'id', 'name', 'description', 'pattern_id', 'pattern_name', 'ifn_regex', 'cl_regex', 'detection_json', 'groups', 'applied_globally', 'last_modified', 'modified_by', 'created_on', 'created_by'
[string[]]$SvFields = 'id', 'value', 'regexp_value', 'value_hash', 'groups', 'applied_globally', 'last_modified', 'modified_by', 'created_on', 'created_by'

# Request the Falcon token using the provided ClientId and ClientSecret
$Token = @{
    ClientId     = $ClientId
    ClientSecret = $ClientSecret
}

if ($PSBoundParameters.ContainsKey('Cloud')) {
    $Token.Cloud = $Cloud
}

if ($PSBoundParameters.ContainsKey('Hostname')) {
    $Token.Hostname = $Hostname
}

Write-Output "Requesting Falcon token..."
Request-FalconToken @Token

# Validate the token
if ((Test-FalconToken).token -ne $true) {
    Write-Error "Failed to retrieve a valid Falcon token. Exiting script."
    exit
}

# Retrieve ML exclusions
Write-Output "Retrieving ML exclusions..."
$RawMlExclusions = Get-FalconMlExclusion -Detailed
Write-Output "Raw ML Exclusions:"
$RawMlExclusions | Format-List

$MlExclusions = $RawMlExclusions | Select-Object $MlFields
if ($MlExclusions -and $MlExclusions.Count -gt 0) {
    Write-Output "ML Exclusions:"
    $MlExclusions | Format-Table -AutoSize
} else {
    Write-Output "No ML exclusions found or failed to retrieve exclusions."
}

# Retrieve IOA exclusions
Write-Output "Retrieving IOA exclusions..."
$RawIoaExclusions = Get-FalconIoaExclusion -Detailed
Write-Output "Raw IOA Exclusions:"
$RawIoaExclusions | Format-List

$IoaExclusions = $RawIoaExclusions | Select-Object $IoaFields
if ($IoaExclusions -and $IoaExclusions.Count -gt 0) {
    Write-Output "IOA Exclusions:"
    $IoaExclusions | Format-Table -AutoSize
} else {
    Write-Output "No IOA exclusions found or failed to retrieve exclusions."
}

# Retrieve Sensor Visibility exclusions
Write-Output "Retrieving Sensor Visibility exclusions..."
$RawSvExclusions = Get-FalconSvExclusion -Detailed
Write-Output "Raw Sensor Visibility Exclusions:"
$RawSvExclusions | Format-List

$SvExclusions = $RawSvExclusions | Select-Object $SvFields
if ($SvExclusions -and $SvExclusions.Count -gt 0) {
    Write-Output "Sensor Visibility Exclusions:"
    $SvExclusions | Format-Table -AutoSize
} else {
    Write-Output "No Sensor Visibility exclusions found or failed to retrieve exclusions."
}

# Export the results based on the specified output format
switch ($OutputFormat) {
    'CSV' {
        Write-Output "Exporting exclusions to CSV files..."
        $MlExclusions | Export-Csv -Path "MlExclusions.csv" -NoTypeInformation
        $IoaExclusions | Export-Csv -Path "IoaExclusions.csv" -NoTypeInformation
        $SvExclusions | Export-Csv -Path "SvExclusions.csv" -NoTypeInformation
        Write-Output "Exclusions have been exported to CSV files."
    }
    'Text' {
        Write-Output "Exporting exclusions to text files..."
        $MlExclusions | Out-File -FilePath "MlExclusions.txt"
        $IoaExclusions | Out-File -FilePath "IoaExclusions.txt"
        $SvExclusions | Out-File -FilePath "SvExclusions.txt"
        Write-Output "Exclusions have been exported to text files."
    }
    'JSON' {
        Write-Output "Exporting exclusions to JSON files..."
        $MlExclusions | ConvertTo-Json | Out-File -FilePath "MlExclusions.json"
        $IoaExclusions | ConvertTo-Json | Out-File -FilePath "IoaExclusions.json"
        $SvExclusions | ConvertTo-Json | Out-File -FilePath "SvExclusions.json"
        Write-Output "Exclusions have been exported to JSON files."
    }
}
