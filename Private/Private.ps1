function Clear-Auth {
    <#
    .SYNOPSIS
        Removes cached authentication and token information
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    process {
        @('Hostname', 'ClientId', 'ClientSecret', 'MemberCid', 'Token').foreach{
            if ($Falcon.$_) {
                $Falcon.$_ = $null
            }
        }
        $Falcon.Expires = Get-Date
    }
}
function Format-Body {
    <#
    .SYNOPSIS
        Converts a 'splat' hashtable body from Get-Param into Json
    .PARAMETER PARAM
        Parameter hashtable
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Param
    )
    process {
        if ($Param.Body -and ($Falcon.GetEndpoint($Param.Endpoint).consumes -eq 'application/json')) {
            # Check 'consumes' value for endpoint and convert body values to Json
            $Param.Body = ConvertTo-Json $Param.Body -Depth 8
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $($Param.Body)"
        }
    }
}
function Format-Header {
    <#
    .SYNOPSIS
        Adds header values to request from endpoint and user input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER REQUEST
        Request object
    .PARAMETER HEADER
        Additional header values to add from user input
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [object] $Request,

        [Parameter()]
        [hashtable] $Header
    )
    begin {
        $Authorization = if ($Endpoint.security -match ".*:(read|write)") {
            # Capture cached token value
            $Falcon.token
        }
        else {
            # Get basic authorization value
            Get-AuthPair
        }
    }
    process {
        if ($Endpoint.consumes) {
            # Add 'consumes' values as 'Content-Type'
            $Request.Headers.Add('ContentType',$Endpoint.consumes)
        }
        if ($Endpoint.produces) {
            # Add 'produces' values as 'Accept'
            $Request.Headers.Add('Accept',$Endpoint.produces)
        }
        if ($Header) {
            foreach ($Pair in $Header.GetEnumerator()) {
                # Add additional header inputs
                $Request.Headers.Add($Pair.Key, $Pair.Value)
            }
        }
        if ($Authorization) {
            # Add authorization
            $Request.Headers.Add('Authorization', $Authorization)
        }
        # Output debug
        $DebugHeader = ($Request.Headers.GetEnumerator()).Where({ $_.Key -NE 'Authorization' }).foreach{
            "$($_.Key): '$($_.Value)'" } -join ', '
        Write-Debug "[$($MyInvocation.MyCommand.Name)] $DebugHeader"
    }
}
function Format-Result {
    <#
    .SYNOPSIS
        Flattens and formats a response from the Falcon API
    .PARAMETER RESPONSE
        Response object from a Falcon API request
    .PARAMETER ENDPOINT
        Falcon endpoint
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Response,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint
    )
    begin {
        # Capture StatusCode from response
        $StatusCode = $Response.Result.StatusCode.GetHashCode()
        $Schema = if ($StatusCode) {
            # Determine 'schema' type from StatusCode
            $Falcon.GetResponse($Endpoint, $StatusCode)
        }
        if ($Response.Result.Content -match '^<') {
            # Output HTML responses as plain strings
            try {
                $HTML = ($Response.Result.Content).ReadAsStringAsync().Result
            }
            catch {
                $_
            }
        }
        elseif ($Response.Result.Content) {
            # Convert Json responses into PowerShell objects
            try {
                $Json = ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
            catch {
                $_
            }
        }
        if ($Json) {
            # Capture 'meta' information to private variable for processing with Invoke-Loop
            Read-Meta -Object $Json -Endpoint $Endpoint -TypeName $Schema
            Write-Debug "[$($MyInvocation.MyCommand.Name)] `r`n$($Json | ConvertTo-Json -Depth 16)"
        }
    }
    process {
        try {
            if ($Json) {
                # Count populated sub-objects in API response
                $Populated = ($Json.PSObject.Properties).Where({ ($_.Name -ne 'meta') -and
                ($_.Name -ne 'errors') }).foreach{
                    if ($_.Value) {
                        $_.Name
                    }
                }
                ($Json.PSObject.Properties).Where({ ($_.Name -eq 'errors') }).foreach{
                    if ($_.Value) {
                        ($_.Value).foreach{
                            $PSCmdlet.WriteError(
                                [System.Management.Automation.ErrorRecord]::New(
                                    [Exception]::New("$($_.code): $($_.message)"),
                                    $Meta.trace_id,
                                    [System.Management.Automation.ErrorCategory]::NotSpecified,
                                    $Response.Result
                                )
                            )
                        }
                    }
                }
                # Format response to output only relevant fields, instead of entire object
                $Output = if ($Populated.count -gt 1) {
                    # For Real-time Response batch session creation, create custom object
                    if ($Populated -eq 'batch_id' -and 'resources') {
                        [PSCustomObject] @{
                            batch_id = $Json.batch_id
                            hosts = $Json.resources.PSObject.Properties.Value
                        }
                    }
                    else {
                        # Output undefined sub-objects
                        $Json
                    }
                }
                elseif ($Populated.count -eq 1) {
                    if ($Populated[0] -eq 'combined') {
                        # If 'combined', return the results under combined
                        $Json.combined.resources.PSObject.Properties.Value
                    }
                    else {
                        # Output sub-object
                        $Json.($Populated[0])
                    }
                }
                else {
                    if ($Meta) {
                        ($Meta.PSObject.Properties.Name).foreach{
                            # Output fields from 'meta' that aren't pagination/diagnostic related
                            if ($_ -notmatch '(entity|pagination|powered_by|query_time|trace_id)' -and $Meta.$_) {
                                if (-not($MetaValues)) {
                                    $MetaValues = [PSCustomObject] @{}
                                }
                                $Name = if ($_ -eq 'writes') {
                                    $Meta.$_.PSObject.Properties.Name
                                }
                                else {
                                    $_
                                }
                                $Value = if ($Name -eq 'resources_affected') {
                                    $Meta.$_.PSObject.Properties.Value
                                }
                                else {
                                    $Meta.$_
                                }
                                $MetaValues.PSObject.Properties.Add((New-Object PSNoteProperty($Name,$Value)))
                            }
                        }
                        if ($MetaValues) {
                            # Output meta values
                            $MetaValues
                        }
                    }
                }
                if ($Output) {
                    # Output formatted result
                    $Output
                }
            }
            elseif ($HTML) {
                # Output HTML
                $HTML
            }
            elseif ($Response.Result.Content) {
                # If unable to convert HTML or Json, output as-is
                ($Response.Result.Content).ReadAsStringAsync().Result
            }
            else {
                # Output request error
                $Response.Result.EnsureSuccessStatusCode()
            }
        }
        catch {
            # Output exception
            $_
        }
    }
}
function Get-AuthPair {
    <#
    .SYNOPSIS
        Outputs a base64 authorization pair for Format-Header
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    process {
        if ($Falcon.ClientId -and $Falcon.ClientSecret) {
            # Convert cached ClientId/ClientSecret to Base64 for basic auth requests
            "basic $([System.Convert]::ToBase64String(
                [System.Text.Encoding]::ASCII.GetBytes("$($Falcon.ClientId):$($Falcon.ClientSecret)")))"
        }
        else {
            $null
        }
    }
}
function Get-Body {
    <#
    .SYNOPSIS
        Outputs body parameters from input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            Add-Type -AssemblyName System.Net.Http
        }
    }
    process {
        foreach ($Item in $Dynamic.Values.Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ((-not $_.Value.in) -or ($_.Value.in -eq 'body')) -and ($_.Value.type -ne 'switch') }).foreach{
                if ($_.Key -eq 'body') {
                    # Convert files sent as 'body' to ByteStream and upload
                    $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                        Get-Content $Item.Value -AsByteStream
                    }
                    else {
                        Get-Content $Item.Value -Encoding Byte -Raw
                    }
                    $ByteArray = [System.Net.Http.ByteArrayContent]::New($ByteStream)
                    $ByteArray.Headers.Add('Content-Type', $Endpoint.produces)
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] File: $($Item.Value)"
                }
                else {
                    if (-not($BodyOutput)) {
                        $BodyOutput = @{}
                    }
                    if ($_.Value.parent) {
                        if (-not($Parents)) {
                            # Construct table to hold child input
                            $Parents = @{}
                        }
                        if (-not($Parents.($_.Value.parent))) {
                            $Parents[$_.Value.parent] = @{}
                        }
                        $Parents.($_.Value.parent)[$_.Key] = $Item.Value
                    }
                    else {
                        # Add input to hashtable for Json conversion
                        $BodyOutput[$_.Key] = $Item.Value
                    }
                }
            }
        }
        if ($Parents) {
            $Parents.GetEnumerator().foreach{
                # Add "Parent" object as array to body
                $BodyOutput[$_.Key] = @( $_.Value )
            }
        }
        if ($BodyOutput) {
            # Output body table
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Body: $($BodyOutput.Keys -join ', ')"
            $BodyOutput
        }
        elseif ($ByteArray) {
            # Output ByteStream
            $ByteArray
        }
    }
}
function Get-Dictionary {
    <#
    .SYNOPSIS
        Creates a dynamic parameter dictionary
    .PARAMETER ENDPOINTS
        An array of 'path:method' endpoint values
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.RuntimeDefinedParameterDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [array] $Endpoints
    )
    begin {
        # Create parameter dictionary
        $Output = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        function Add-Parameter ($Parameter) {
            ($Parameter.GetEnumerator()).foreach{
                # Create parameters defined by endpoint
                $Attribute = New-Object System.Management.Automation.ParameterAttribute
                $Attribute.ParameterSetName = $_.Value.set
                $Attribute.Mandatory = $_.Value.required
                if ($_.Value.description) {
                    $Attribute.HelpMessage = $_.Value.description
                }
                if ($_.Value.position) {
                    $Attribute.Position = $_.Value.position
                }
                if ($_.Value.pipeline) {
                    $Attribute.ValueFromPipeline = $_.Value.pipeline
                }
                if ($Output.($_.Value.dynamic)) {
                    $Output.($_.Value.dynamic).Attributes.add($Attribute)
                }
                else {
                    $Collection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                    $Collection.Add($Attribute)
                    $PSType = switch ($_.Value.type) {
                        'array' { [array] }
                        'boolean' { [bool] }
                        'double' { [double] }
                        'integer' { [int] }
                        'int32' { [Int32] }
                        'int64' { [Int64] }
                        'object' { [object] }
                        'switch' { [switch] }
                        default { [string] }
                    }
                    if ($_.Value.required -eq $false) {
                        $Collection.Add((New-Object Management.Automation.ValidateNotNullOrEmptyAttribute))
                    }
                    if ($_.Value.enum) {
                        $ValidSet = New-Object System.Management.Automation.ValidateSetAttribute($_.Value.enum)
                        $ValidSet.IgnoreCase = $false
                        $Collection.Add($ValidSet)
                    }
                    if ($_.Value.min -and $_.Value.max) {
                        if ($PSType -eq [int]) {
                            # Set range min/max for integers
                            $Collection.Add((New-Object Management.Automation.ValidateRangeAttribute(
                                $_.Value.Min, $_.Value.Max)))
                        }
                        elseif ($PSType -eq [string]) {
                            # Set length min/max for strings
                            $Collection.Add((New-Object Management.Automation.ValidateLengthAttribute(
                                    $_.Value.Min, $_.Value.Max)))
                        }
                    }
                    if ($_.Value.pattern) {
                        # Set RegEx validation pattern
                        $Collection.Add((New-Object Management.Automation.ValidatePatternAttribute(
                            ($_.Value.pattern).ToString())))
                    }
                    if ($_.Value.script) {
                        # Set ValidationScript
                        $ValidScript = New-Object Management.Automation.ValidateScriptAttribute(
                            [scriptblock]::Create($_.Value.script))
                        if ($_.Value.scripterror -and $ValidScript.ErrorMessage) {
                            $ValidScript.ErrorMessage = $_.Value.scripterror
                        }
                        $Collection.Add($ValidScript)
                    }
                    # Add parameter to dictionary
                    $RunParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
                        $_.Value.dynamic, $PSType, $Collection)
                    $Output.Add($_.Value.dynamic, $RunParam)
                }
            }
        }
    }
    process {
        foreach ($Endpoint in $Endpoints) {
            # Add parameters from each endpoint
            $Falcon.GetEndpoint($Endpoint).Parameters.foreach{
                Add-Parameter -Parameter $_
            }
        }
        ($Endpoints -match '/queries/').foreach{
            if ($Endpoints -match '(/entities/|/combined/)') {
                # Add 'Detailed' parameter when both 'queries' and 'entities/combined' endpoints are present
                Add-Parameter @{
                    detailed = @{
                        dynamic = 'Detailed'
                        set = $_
                        type = 'switch'
                        description = 'Retrieve detailed information'
                    }
                }
            }
            if ($Output.Offset -or $Output.After) {
                # Add 'All' switch when using a 'queries' endpoint that has pagination parameters
                Add-Parameter @{
                    all = @{
                        dynamic = 'All'
                        set = $_
                        type = 'switch'
                        description = 'Repeat requests until all available results are retrieved'
                    }
                }
            }
        }
        # Add 'Help' to all endpoints
        Add-Parameter @{
            help = @{
                dynamic = 'Help'
                set = 'psfalcon:help'
                type = 'switch'
                required = $true
                description = 'Output dynamic help information'
            }
        }
        # Output dictionary
        return $Output
    }
}
function Get-DynamicHelp {
    <#
    .SYNOPSIS
        Outputs basic information about dynamic parameters
    .PARAMETER COMMAND
        PSFalcon command name(s)
    .PARAMETER EXCLUSIONS
        Endpoints to exclude from results (for redundancies)
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter()]
        [array] $Exclusions
    )
    begin {
        # Default PowerShell parameters to exclude from output
        $Defaults = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable',
            'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
        $ParamSets = foreach ($Set in ((Get-Command $Command).ParameterSets).Where({
        ($_.Name -ne 'psfalcon:help') -and ($Exclusions -notcontains $_.Name) })) {
            # Gather endpoint data using 'ParameterSets' defined by 'Get-Dictionary', minus Exclusions
            ($Falcon.GetEndpoint($Set.Name)).foreach{
                # Create custom object for each endpoint
                @{
                    $Set.Name = @{
                        Description = $_.Description
                        Permission  = $_.Security
                        Parameters  = ($Set.Parameters).Where({ $Defaults -notcontains $_.Name }).foreach{
                            $Parameter = [ordered] @{
                                Name        = $_.Name
                                Type        = $_.ParameterType.name
                                Required    = $_.IsMandatory
                                Description = $_.HelpMessage
                            }
                            if ($_.Position -gt 0) {
                                $Parameter['Position'] = $_.Position
                            }
                            foreach ($Attribute in @('ValidValues', 'RegexPattern', 'MinLength', 'MaxLength',
                                'MinRange', 'MaxRange')) {
                                $Name = switch -Regex ($Attribute) {
                                    'ValidValues' { 'Values' }
                                    'RegexPattern' { 'Pattern' }
                                    '(MinLength|MinRange)' { 'Minimum' }
                                    '(MaxLength|MaxRange)' { 'Maximum' }
                                }
                                if ($_.Attributes.$Attribute) {
                                    $Value = if ($_.Attributes.$Attribute -is [array]) {
                                        $_.Attributes.$Attribute -join ', '
                                    }
                                    else {
                                        $_.Attributes.$Attribute
                                    }
                                    $Parameter[$Name] = $Value
                                }
                            }
                            $Parameter
                        }
                    }
                }
            }
        }
        function Show-Parameter ($Parameter) {
            # Output endpoint object as string
            if ($_.Name) {
                $Label = "`n  -$($_.Name) [$($_.Type)]"
                if ($_.Required -eq $true) {
                    $Label += " <Required>"
                }
                $Label + "`n    $($_.Description)"
            }
            (($_.GetEnumerator()).Where({ $_.Key -notmatch
            '(Name|Type|Required|Description)' })).foreach{
                    "      $($_.Key) : $($_.Value)"
            }
        }
    }
    process {
        ($ParamSets).foreach{
            ($_.GetEnumerator()).foreach{
                # Output endpoint description and permission
                "`n# $($_.Value.Description)"
                if ($_.Value.Permission) {
                    "  Requires $($_.Value.Permission)"
                }
                if ($_.Value.Parameters) {
                    # Output each individual parameter for endpoint
                    (($_.Value.Parameters).Where({ $_.Type -notmatch 'SwitchParameter' }) |
                    Sort-Object { $_.Position }).foreach{
                        Show-Parameter $_
                    }
                    ($_.Value.Parameters).Where({ $_.Type -match 'SwitchParameter' }).foreach{
                        Show-Parameter $_
                    }
                }
            }
        }
        "`n"
    }
}
function Get-Formdata {
    <#
    .SYNOPSIS
        Outputs 'Formdata' dictionary from input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in $Dynamic.Values.Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ($_.Value.In -eq 'formdata') }).foreach{
                # Construct formdata table
                if (-not($FormdataOutput)) {
                    $FormdataOutput = @{}
                }
                $Value = if ($_.Key -eq 'content') {
                    # Collect file content as a string
                    [string] (Get-Content $Item.Value -Raw)
                }
                else {
                    $Item.Value
                }
                $FormdataOutput[$_.Key] = $Value
            }
        }
        if ($FormdataOutput) {
            # Output formdata table
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $(ConvertTo-Json $FormdataOutput)"
            $FormdataOutput
        }
    }
}
function Get-Header {
    <#
    .SYNOPSIS
        Outputs a hashtable of header values from input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in $Dynamic.Values.Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ($_.Value.In -eq 'header') }).foreach{
                # Construct header table
                if (-not($HeaderOutput)) {
                    $HeaderOutput = @{}
                }
                $HeaderOutput[$_.Key] = $Item.Value
            }
        }
        if ($HeaderOutput) {
            # Output header table
            $HeaderOutput
        }
    }
}
function Get-LoopParam {
    <#
    .SYNOPSIS
        Creates a 'splat' hashtable for Invoke-Loop
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        $Output = @{}
    }
    process {
        foreach ($Item in ($Dynamic.Values).Where({ ($_.IsSet -eq $true) -and
        ($_.Name -notmatch '(offset|after|all|detailed)') })) {
            # Add dynamic inputs, but exclude parameters that will break Invoke-Loop
            $Output[$Item.Name] = $Item.Value
        }
        $Output
    }
}
function Get-Outfile {
    <#
    .SYNOPSIS
        Corrects relative user path inputs for 'outfile' content
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in $Dynamic.Values.Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $FileOutput = $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ($_.Value.In -eq 'outfile') }).foreach{
                # Convert relative paths to $pwd
                $Item.Value -replace '^\.', $pwd
            }
            if ($FileOutput) {
                # Output file path string
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $FileOutput"
                $FileOutput
            }
        }
    }
}
function Get-Param {
    <#
    .SYNOPSIS
        Creates a 'splat' hashtable for Invoke-Endpoint
    .PARAMETER ENDPOINT
        Falcon endpoint name
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    .PARAMETER MAX
        A maximum number of identifiers per request
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic,

        [Parameter()]
        [int] $Max
    )
    begin {
        # Construct output table and gather information about endpoint
        $Output = @{
            Endpoint = $Endpoint
        }
        $Target = $Falcon.GetEndpoint($Endpoint)
    }
    process {
        @('Body', 'Formdata', 'Header', 'Outfile', 'Path', 'Query').foreach{
            # Create key/value pairs for each "Get-<Input>" function
            $Value = & "Get-$_" -Endpoint $Target -Dynamic $Dynamic
            if ($Value) {
                $Output[$_] = $Value
            }
        }
        # Pass parameter sets to Split-Param
        $Param = @{
            Param = $Output
        }
        if ($Max) {
            $Param['Max'] = $Max
        }
        Split-Param @Param
    }
}
function Get-Path {
    <#
    .SYNOPSIS
        Modifies an endpoint 'path' value based on input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        $PathOutput = $Endpoint.Path
    }
    process {
        foreach ($Item in $Dynamic.Values.Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $PathOutput = $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ($_.Value.In -eq 'path') }).foreach{
                $Endpoint.path -replace $_.Key, $Item.Value
            }
            if ($PathOutput) {
                # Output new URI path
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $PathOutput"
                $PathOutput
            }
        }
    }
}
function Get-Query {
    <#
    .SYNOPSIS
        Outputs an array of query values from user input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        # Check for relative "last X days/hours" filter values and convert them to RFC-3339
        if ($Dynamic.Filter.Value) {
            $Relative = "(last (?<Int>\d{1,}) (day[s]?|hour[s]?))"
            if ($Dynamic.Filter.Value -match $Relative) {
                $Dynamic.Filter.Value | Select-String $Relative -AllMatches | ForEach-Object {
                    foreach ($Match in $_.Matches.Value) {
                        [int] $Int = $Match -replace $Relative, '${Int}'
                        if ($Match -match "day") {
                            $Int = $Int * -24
                        } else {
                            $Int = $Int * -1
                        }
                        $Dynamic.Filter.Value = $Dynamic.Filter.Value -replace $Match, $Falcon.Rfc3339($Int)
                    }
                }
            }
        }
    }
    process {
        $QueryOutput = foreach ($Item in ($Dynamic.Values).Where({ $_.IsSet -eq $true })) {
            # Match dynamic parameters to parameters defined by endpoint
            $Endpoint.parameters.GetEnumerator().Where({ ($_.Value.dynamic -eq $Item.Name) -and
            ($_.Value.in -eq 'query') }).foreach{
                foreach ($Value in $Item.Value) {
                    # Output "query" values to an array and encode '+' to ensure filter input integrity
                    if ($_.Key) {
                        if (($Endpoint.path -eq '/indicators/queries/iocs/v1') -and (($_.Key -eq 'type') -or 
                        ($_.Key -eq 'value'))) {
                            # Change type/value to types/values for /indicators/queries/iocs/v1:get
                            ,"$($_.Key)s=$($Value -replace '\+','%2B')"
                        }
                        else {
                            ,"$($_.Key)=$($Value -replace '\+','%2B')"
                        }
                    }
                    else {
                        ,"$($Value -replace '\+','%2B')"
                    }
                }
            }
        }
        if ($QueryOutput) {
            # Trim pagination tokens for verbose output and output query array
            $VerboseOutput = (($QueryOutput).foreach{
                if (($_ -match '^offset=') -and ($_.Length -gt 14)) {
                    "$($_.Substring(0,13))..."
                }
                elseif (($_ -match '^after=') -and ($_.Length -gt 13)) {
                    "$($_.Substring(0,12))..."
                }
                else {
                    $_
                }
            }) -join ', '
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $VerboseOutput"
            $QueryOutput
        }
    }
}
function Invoke-Endpoint {
    <#
    .SYNOPSIS
        Makes a request to a Falcon API endpoint
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER HEADER
        Header key/value pair user input
    .PARAMETER QUERY
        An array of string values to append to the URI path
    .PARAMETER BODY
        User body string input
    .PARAMETER FORMDATA
        Formdata dictionary from user input
    .PARAMETER OUTFILE
        Path for 'outfile' output
    .PARAMETER PATH
        A modified 'path' value to use in place of the endpoint-defined string
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter()]
        [hashtable] $Header,

        [Parameter()]
        [array] $Query,

        [Parameter()]
        [object] $Body,

        [Parameter()]
        [System.Collections.IDictionary] $Formdata,

        [Parameter()]
        [string] $Outfile,

        [Parameter()]
        [string] $Path
    )
    begin {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            Add-Type -AssemblyName System.Net.Http
        }
        if ((-not($Falcon.Token)) -or (($Falcon.Expires) -le (Get-Date).AddSeconds(30)) -and
        ($Endpoint -ne '/oauth2/token:post')) {
            # Check for expired/expiring tokens and force an OAuth2 token request
            Request-FalconToken
        }
        # Gather endpoint data
        $Target = $Falcon.GetEndpoint($Endpoint)
        $FullUri = if ($Path) {
            # Append URI path with Hostname and user input
            "$($Falcon.Hostname)$($Path)"
        }
        else {
            # Append URI path with Hostname
            "$($Falcon.Hostname)$($Target.Path)"
        }
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $($Target.Method.ToUpper()) $FullUri"
        if ($Query) {
            # Appent query inputs to URI path
            $FullUri += "?$($Query -join '&')"
        }
    }
    process {
        # Create System.Net.Http base object and append request header
        $Client = [System.Net.Http.HttpClient]::New()
        $Request = [System.Net.Http.HttpRequestMessage]::New($Target.Method.ToUpper(), [System.Uri]::New($FullUri))
        $Param = @{
            Endpoint = $Target
            Request = $Request
        }
        if ($Header) {
            $Param['Header'] = $Header
        }
        Format-Header @Param
        if ($Query -match 'timeout') {
            # Add timeout value to request if found in query inputs from Real-time Response commands
            $Timeout = [int] (($Query).Where({ $_ -match 'timeout' })).Split('=')[1] + 5
            $Client.Timeout = (New-TimeSpan -Seconds $Timeout).Ticks
            Write-Verbose ("[$($MyInvocation.MyCommand.Name)] HttpClient timeout set to $($Timeout) seconds")
        }
        try {
            if ($Formdata) {
                # Create formdata object
                $MultiContent = [System.Net.Http.MultipartFormDataContent]::New()
                foreach ($Key in $Formdata.Keys) {
                    if ($Key -match '(file|upfile)') {
                        # Append files defined by dynamic parameters
                        $FileStream = [System.IO.FileStream]::New($Formdata.$Key, [System.IO.FileMode]::Open)
                        $Filename = [System.IO.Path]::GetFileName($Formdata.$Key)
                        $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
                        $MultiContent.Add($StreamContent, $Key, $Filename)
                    }
                    else {
                        # Add content as strings
                        $StringContent = [System.Net.Http.StringContent]::New($Formdata.$Key)
                        $MultiContent.Add($StringContent, $Key)
                    }
                }
                # Append formdata object to request
                $Request.Content = $MultiContent
            }
            elseif ($Body) {
                $Request.Content = if ($Body -is [string]) {
                    # Append Json body to request using endpoint's 'consumes' value
                    [System.Net.Http.StringContent]::New($Body, [System.Text.Encoding]::UTF8, $Target.consumes)
                }
                else {
                    # Append body to request directly
                    $Body
                }
            }
            $Response = if ($Outfile) {
                # Add 'outfile' to header and receive payload
                ($Request.Headers.GetEnumerator()).foreach{
                    $Client.DefaultRequestHeaders.Add($_.Key, $_.Value)
                }
                $Request.Dispose()
                $Client.GetByteArrayAsync($Uri)
            }
            else {
                # Make request
                $Client.SendAsync($Request)
            }
            if ($Response.Result -is [System.Byte[]]) {
                # Write file payload to 'outfile' path
                [System.IO.File]::WriteAllBytes($Outfile, ($Response.Result))
                if (Test-Path $Outfile) {
                    Get-ChildItem $Outfile | Out-Host
                }
            }
            elseif ($Response.Result) {
                # Format responses
                Format-Result -Response $Response -Endpoint $Endpoint
            }
            else {
                # Output error
                $PSCmdlet.WriteError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [Exception]::New("Unable to contact $($Falcon.Hostname)"),
                        "psfalcon_connection_failure",
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $Response
                    )
                )
            }
        }
        catch {
            # Output exception
            $_
        }
    }
    end {
        if ($Response.Result.Headers) {
            # Wait for 'X-Ratelimit-RetryAfter'
            Wait-RetryAfter $Response.Result.Headers
        }
        if ($Response) {
            $Response.Dispose()
        }
    }
}
function Invoke-Loop {
    <#
    .SYNOPSIS
        Watches 'meta' results to repeat command requests
    .PARAMETER COMMAND
        The PSFalcon command to repeat
    .PARAMETER PARAM
        Parameters to include when running the command
    .PARAMETER DETAILED
        Toggle the 'Detailed' switch during command request
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter(Mandatory = $true)]
        [hashtable] $Param,

        [Parameter()]
        [bool] $Detailed
    )
    begin {
        function Set-Paging ($Object, $Param, $Count) {
            # Check 'Meta' object from Format-Result for pagination information
            if ($Object.after) {
                $Param['After'] = $Object.after
            }
            else {
                if ($Object.next_page) {
                    $Param['Offset'] = $Object.offset
                }
                else {
                    $Param['Offset'] = if ($Object.offset -match '^\d{1,}$') {
                        $Count
                    }
                    else {
                        $Object.offset
                    }
                }
            }
        }
    }
    process {
        # Perform initial request
        $Loop = @{
            Request = & $Command @Param
            Pagination = $Meta.pagination
        }
        if ($Loop.Request -and $Detailed) {
            # Perform secondary request for identifier detail
            & $Command -Ids $Loop.Request
        }
        else {
            $Loop.Request
        }
        if ($Loop.Request -and (($Loop.Request.count -lt $Loop.Pagination.total) -or $Loop.Pagination.next_page)) {
            for ($i = $Loop.Request.count; ($Loop.Pagination.next_page -or ($i -lt $Loop.Pagination.total));
            $i += $Loop.Request.count) {
                # Repeat requests if additional results are defined in 'meta'
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] retrieved $i results"
                Set-Paging -Object $Loop.Pagination -Param $Param -Count $i
                $Loop = @{
                    Request = & $Command @Param
                    Pagination = $Meta.pagination
                }
                if ($Loop.Request -and $Detailed) {
                    & $Command -Ids $Loop.Request
                }
                else {
                    $Loop.Request
                }
            }
        }
    }
}
function Invoke-Request {
    <#
    .SYNOPSIS
        Determines request type and submits to Invoke-Loop or Invoke-Endpoint
    .PARAMETER COMMAND
        PSFalcon command calling Invoke-Request [required for -All and -Detailed]
    .PARAMETER QUERY
        The Falcon endpoint that for 'queries' operations
    .PARAMETER ENTITY
        The Falcon endpoint that for 'entities' operations
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for user input values
    .PARAMETER DETAILED
        Toggle the use of 'Detailed' with a command when using Invoke-Loop
    .PARAMETER MODIFIER
        The name of a switch parameter used to modify a command when using Invoke-Loop
    .PARAMETER ALL
        Toggle the use of Invoke-Loop to repeat command requests
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter()]
        [string] $Command,

        [Parameter(Mandatory = $true)]
        [string] $Query,

        [Parameter()]
        [string] $Entity,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic,

        [Parameter()]
        [bool] $Detailed,

        [Parameter()]
        [string] $Modifier,

        [Parameter()]
        [switch] $All
    )
    begin {
        # Set base endpoint based on dynamic input
        $Endpoint = if (($Dynamic.Values).Where({ $_.IsSet -eq $true }).Attributes.ParameterSetName -eq $Entity) {
            $Entity
        }
        else {
            $Query
        }
    }
    process {
        if ($All) {
            # Construct parameters and pass to Invoke-Loop
            $LoopParam = @{
                Command = $Command
                Param = Get-LoopParam -Dynamic $Dynamic
            }
            if ($Endpoint -match '/combined/.*:get$') {
                $LoopParam.Param['Detailed'] = $true
            }
            if ($Detailed) {
                $LoopParam['Detailed'] = $true
            }
            if ($Modifier) {
                $LoopParam.Param[$Modifier] = $true
            }
            Invoke-Loop @LoopParam
        }
        else {
            foreach ($Param in (Get-Param -Endpoint $Endpoint -Dynamic $Dynamic)) {
                # Format Json body and make request
                Format-Body -Param $Param
                $Request = Invoke-Endpoint @Param
                if ($Request -and $Detailed) {
                    # Make secondary request for detail about identifiers
                    & $Command -Ids $Request
                }
                else {
                    $Request
                }
            }
        }
    }
}
function Read-Meta {
    <#
    .SYNOPSIS
        Outputs verbose 'meta' information and creates $Script:Meta for loop processing
    .PARAMETER OBJECT
        Object from a Falcon API request
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER TYPENAME
        Optional 'meta' object typename, sourced from API response code/definition
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Object,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter()]
        [string] $TypeName
    )
    begin {
        function Read-CountValue ($Property, $Prefix) {
            # Output 'meta' values
            if ($_.Value -is [PSCustomObject]) {
                $ItemPrefix = $_.Name
                ($_.Value.PSObject.Properties).foreach{
                    Read-CountValue -Property $_ -Prefix $ItemPrefix
                }
            }
            elseif ($_.Name -match '(after|offset|total)') {
                $Value = if (($_.Value -is [string]) -and ($_.Value.Length -gt 7)) {
                    "$($_.Value.Substring(0,6))..."
                }
                else {
                    $_.Value
                }
                $Name = if ($Prefix) {
                    "$($Prefix)_$($_.Name)"
                }
                else {
                    $_.Name
                }
                if ($Name -and $Value) {
                    "$($Name): $($Value)"
                }
            }
        }
    }
    process {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] $($StatusCode): $TypeName"
        if ($Object.meta) {
            # Create script 'meta' variable for internal reference
            $Script:Meta = $Object.meta
            if ($TypeName) {
                # Set object typename to 'schema' from response
                $Meta.PSObject.TypeNames.Insert(0,$TypeName)
            }
        }
        if ($Meta) {
            if ($Meta.trace_id) {
                # Output trace_id
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] trace_id: $($Meta.trace_id)"
            }
            $CountInfo = (($Meta.PSObject.Properties).foreach{
                # Output pagination
                Read-CountValue $_
            }) -join ', '
            if ($CountInfo) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $CountInfo"
            }
        }
    }
}
function Split-Param {
    <#
    .SYNOPSIS
        Splits 'splat' hashtables into smaller groups to avoid API limitations
    .PARAMETER PARAM
        Parameter hashtable
    .PARAMETER MAX
        A manually-defined maximum number of identifiers per request
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Param,

        [Parameter()]
        [int] $Max
    )
    begin {
        if (-not($Max)) {
            # Gather endpoint information
            $Endpoint = $Falcon.GetEndpoint($Param.Endpoint)
            $Max = if ($Output.Query -match 'ids=') {
                # Calculate URL length based on hostname, endpoint path and input
                $PathLength = ("$($Falcon.Hostname)$($Endpoint.Path)").Length
                $LongestId = (($Output.Query).Where({ $_ -match 'ids='}) |
                    Measure-Object -Maximum -Property Length).Maximum + 1
                $IdCount = [Math]::Floor([decimal]((65535 - $PathLength)/$LongestId))
                if ($IdCount -gt 1000) {
                    # Set maximum for requests to 1,000
                    1000
                }
                else {
                    # Use maximum below 1,000
                    $IdCount
                }
            } elseif ($Endpoint.parameters -and ($Endpoint.Parameters.GetEnumerator().Where({
            $_.Key -eq 'ids' }).Value.max -gt 0)) {
                # Use maximum defined by endpoint
                $Endpoint.parameters.GetEnumerator().Where({ $_.Key -eq 'ids' }).Value.max
            } else {
                $null
            }
        }
    }
    process {
        if ($Max -and $Param.Query.count -gt $Max) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $Max query values per request"
            for ($i = 0; $i -lt $Param.Query.count; $i += $Max) {
                # Break query inputs into groups that are lower than maximum
                $Group = @{
                    Query = $Param.Query[$i..($i + ($Max - 1))]
                }
                ($Param.Keys).foreach{
                    if ($_ -ne 'Query') {
                        $Group[$_] = $Param.$_
                    }
                }
                $Group
            }
        } elseif ($Max -and $Param.Body.ids.count -gt $Max) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $Max body values per request"
            for ($i = 0; $i -lt $Param.Body.ids.count; $i += $Max) {
                # Break body inputs into groups that are lower than maximum
                $Group = @{
                    Body = @{
                        ids = $Param.Body.ids[$i..($i + ($Max - 1))]
                    }
                }
                ($Param.Keys).foreach{
                    if ($_ -ne 'Body') {
                        $Group[$_] = $Param.$_
                    } else {
                        (($Param.$_).Keys).foreach{
                            if ($_ -ne 'ids') {
                                $Group.Body[$_] = $Param.Body.$_
                            }
                        }
                    }
                }
                $Group
            }
        } else {
            # If maximum is not exceeded, output as-is
            $Param
        }
    }
}
function Wait-RetryAfter {
    <#
    .SYNOPSIS
        Checks a Falcon API response for rate limiting and waits
    .PARAMETER HEADERS
        Response headers from Falcon endpoint
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Headers
    )
    process {
        if ($Headers.Key -contains 'X-Ratelimit-RetryAfter') {
            # Determine wait time from response header and sleep
            $RetryAfter = (($Headers.GetEnumerator()).Where({ $_.Key -eq 'X-Ratelimit-RetryAfter' })).Value
            $Wait = ($RetryAfter - ([int] (Get-Date -UFormat %s) + 1))
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] rate limited for $Wait seconds"
            Start-Sleep -Seconds $Wait
        }
    }
}