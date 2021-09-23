function Add-Property {
    [CmdletBinding()]
    param(
        [object] $Object,
        [string] $Name,
        [object] $Value
    )
    process {
        # Add property to [PSCustomObject]
        $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
    }
}
function Build-Content {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [object] $Format,
        [object] $Inputs
    )
    begin {
        function Build-Body ($Format, $Inputs) {
            $Body = @{}
            $Inputs.GetEnumerator().Where({ $Format.Body.Values -match $_.Key }).foreach{
                $Field = ($_.Key).ToLower()
                $Value = if ($_.Value -is [string] -and $_.Value -eq 'null') {
                    # Convert [string] values of 'null' to null values
                    $null
                } elseif ($_.Value -is [array]) {
                    ,($_.Value).foreach{
                        if ($_ -is [string] -and $_ -eq 'null') {
                            # Convert [string] values of 'null' to null values
                            $null
                        } else {
                            $_
                        }
                    }
                } else {
                    $_.Value
                }
                if ($Field -eq 'body') {
                    # Add 'body' value as [System.Net.Http.ByteArrayContent]
                    $FullFilePath = $Script:Falcon.Api.Path($_.Value)
                    Write-Verbose "[Build-Body] '$FullFilePath'"
                    $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                        Get-Content $FullFilePath -AsByteStream
                    } else {
                        Get-Content $FullFilePath -Encoding Byte -Raw
                    }
                    $ByteArray = [System.Net.Http.ByteArrayContent]::New($ByteStream)
                    $ByteArray.Headers.Add('Content-Type', $Headers.ContentType)
                } else {
                    if (!$Body) {
                        $Body = @{}
                    }
                    if (($Value -is [array] -or $Value -is [string]) -and $Value | Get-Member -MemberType Method |
                    Where-Object { $_.Name -eq 'Normalize' }) {
                        # Normalize values to avoid Json conversion errors when 'Get-Content' was used
                        if ($Value -is [array]) {
                            $Value = [array] ($Value).Normalize()
                        } elseif ($Value -is [string]) {
                            $Value = ($Value).Normalize()
                        }
                    }
                    $Format.Body.GetEnumerator().Where({ $_.Value -eq $Field }).foreach{
                        if ($_.Key -eq 'root') {
                            # Add key/value pair directly to 'Body'
                            $Body.Add($Field, $Value)
                        } else {
                            # Create parent object and add key/value pair
                            if (!$Parents) {
                                $Parents = @{}
                            }
                            if (!$Parents.($_.Key)) {
                                $Parents[$_.Key] = @{}
                            }
                            $Parents.($_.Key).Add($Field, $Value)
                        }
                    }
                }
            }
            if ($ByteArray) {
                # Return 'ByteArray' object
                $ByteArray
            } else {
                if ($Parents) {
                    $Parents.GetEnumerator().foreach{
                        # Add parents as arrays in 'Body'
                        $Body[$_.Key] = @( $_.Value )
                    }
                }
                if (($Body.Keys | Measure-Object).Count -gt 0) {
                    # Return 'Body' object
                    Write-Verbose "[Build-Body] $(ConvertTo-Json -InputObject $Body -Depth 32 -Compress)"
                    $Body
                }
            }
        }
        function Build-Formdata ($Format, $Inputs) {
            $Formdata = @{}
            $Inputs.GetEnumerator().Where({ $Format.Formdata -contains $_.Key }).foreach{
                $Formdata[($_.Key).ToLower()] = if ($_.Key -eq 'content') {
                    # Collect file content as a string
                    [string] (Get-Content ($Script:Falcon.Api.Path($_.Value)) -Raw)
                } else {
                    $_.Value
                }
            }
            if (($Formdata.Keys | Measure-Object).Count -gt 0) {
                # Return 'Formdata' object
                Write-Verbose "[Build-Formdata] $(ConvertTo-Json -InputObject $Formdata -Depth 32 -Compress)"
                $Formdata
            }
        }
        function Build-Query ($Format, $Inputs) {
            # Regex pattern for matching 'last [int] days/hours'
            [regex] $Relative = '(last (?<Int>\d{1,}) (day[s]?|hour[s]?))'
            [array] $Query = $Inputs.GetEnumerator().Where({ $Format.Query -contains $_.Key }).foreach{
                $Field = ($_.Key).ToLower()
                ($_.Value).foreach{
                    $Value = $_
                    if ($Field -eq 'filter' -and $Value -match $Relative) {
                        # Convert 'last [int] days/hours' to Rfc3339
                        $Value | Select-String $Relative -AllMatches | ForEach-Object {
                            foreach ($Match in $_.Matches.Value) {
                                [int] $Int = $Match -replace $Relative, '${Int}'
                                $Int = if ($Match -match 'day') {
                                    $Int * -24
                                } else {
                                    $Int * -1
                                }
                                $Value = $Value -replace $Match, (Convert-Rfc3339 $Int)
                            }
                        }
                    }
                    # Output array of strings to append to 'Path' and HTML-encode '+'
                    ,"$($Field)=$($Value -replace '\+','%2B')"
                }
            }
            if ($Query) {
                # Return 'Query' array
                $Query
            }
        }
    }
    process {
        if ($Inputs) {
            $Content = @{}
            @('Body', 'Formdata', 'Outfile', 'Query').foreach{
                if ($Format.$_) {
                    $Value = if ($_ -eq 'Outfile') {
                        # Get absolute path for 'OutFile'
                        $Outfile = $Inputs.GetEnumerator().Where({ $Format.Outfile -eq $_.Key }).Value
                        if ($Outfile) {
                            $Script:Falcon.Api.Path($Outfile)
                        }
                    } else {
                        # Get value(s) from each 'Build' function
                        & "Build-$_" -Format $Format -Inputs $Inputs
                    }
                    if ($Value) {
                        $Content[$_] = $Value
                    }
                }
            }
        }
    }
    end {
        if (($Content.Keys | Measure-Object).Count -gt 0) {
            # Return 'Content' table
            $Content
        }
    }
}
function Confirm-Parameter {
    [CmdletBinding()]
    [OutputType([boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Object,

        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter()]
        [array] $Required,

        [Parameter()]
        [array] $Allowed,

        [Parameter()]
        [array] $Content,

        [Parameter()]
        [array] $Pattern,

        [Parameter()]
        [object] $Format
    )
    begin {
        function Get-ValidPattern ($Command, $Endpoint, $Parameter) {
            # Return 'ValidPattern' from parameter of a given command
            (Get-Command $Command).ParameterSets.Where({ $_.Name -eq $Endpoint }).Parameters.Where({
                $_.Name -eq $Parameter }).Attributes.RegexPattern
        }
        function Get-ValidValues ($Command, $Endpoint, $Parameter) {
            # Return 'ValidValues' from parameter of a given command
            (Get-Command $Command).ParameterSets.Where({ $_.Name -eq $Endpoint }).Parameters.Where({
                $_.Name -eq $Parameter }).Attributes.ValidValues
        }
        # Create object string
        $ObjectString = ConvertTo-Json -InputObject $Object -Depth 32 -Compress
    }
    process {
        if ($Object -is [hashtable]) {
            ($Required).foreach{
                # Verify object contains required fields
                if ($Object.Keys -notcontains $_) {
                    throw "Missing '$_'. $ObjectString"
                } else {
                    $true
                }
            }
            if ($Allowed) {
                ($Object.Keys).foreach{
                    if ($Allowed -notcontains $_) {
                        # Error if field is not in allowed list
                        throw "Unexpected '$_'. $ObjectString"
                    } else {
                        $true
                    }
                }
            }
        } elseif ($Object -is [PSCustomObject]) {
            ($Required).foreach{
                # Verify object contains required fields
                if ($Object.PSObject.Members.Where({ $_.MemberType -eq 'NoteProperty' }).Name -notcontains $_) {
                    throw "Missing '$_'. $ObjectString"
                } else {
                    $true
                }
            }
            if ($Allowed) {
                ($Object.PSObject.Members.Where({ $_.MemberType -eq 'NoteProperty' }).Name).foreach{
                    if ($Allowed -notcontains $_) {
                        # Error if field is not in allowed list
                        throw "Unexpected '$_'. $ObjectString"
                    } else {
                        $true
                    }
                }
            }
        }
        ($Content).foreach{
            $Parameter = if ($Format -and $Format.$_) {
                # Match property name with parameter name
                $Format.$_
            } else {
                $_
            }
            if ($Object.$_) {
                # Verify that 'ValidValues' contains provided value
                $ValidValues = Get-ValidValues -Command $Command -Endpoint $Endpoint -Parameter $Parameter
                if ($Object.$_ -is [array]) {
                    foreach ($Item in $Object.$_) {
                        if ($ValidValues -notcontains $Item) {
                            "'$($Item)' is not a valid '$_' value. $ObjectString"
                        }
                    }
                } elseif ($ValidValues -notcontains $Object.$_) {
                    throw "'$($Object.$_)' is not a valid '$_' value. $ObjectString"
                }
            }
        }
        ($Pattern).foreach{
            $Parameter = if ($Format -and $Format.$_) {
                # Match property name with parameter name
                $Format.$_
            } else {
                $_
            }
            if ($Object.$_) {
                # Verify provided value matches 'ValidPattern'
                $ValidPattern = Get-ValidPattern -Command $Command -Endpoint $Endpoint -Parameter $Parameter
                if ($Object.$_ -notmatch $ValidPattern) {
                    throw "'$($Object.$_)' is not a valid '$_' value. $ObjectString"
                }
            }
        }
    }
}
function Confirm-String {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $String
    )
    begin {
        # RegEx patterns
        $RegEx = @{
            md5    = [regex] '^[A-Fa-f0-9]{32}$'
            sha256 = [regex] '^[A-Fa-f0-9]{64}$'
            ipv4   = [regex] '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.'
            ipv6   = [regex] '^[0-9a-fA-F]{1,4}:'
            domain = [regex] '^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$'
            email  = [regex] "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"
        }
    }
    process {
        $Output = ($RegEx.GetEnumerator()).foreach{
            if ($String -match $_.Value) {
                if ($_.Key -match '^(ipv4|ipv6)$') {
                    if (($String -as [System.Net.IPAddress] -as [bool]) -eq $true) {
                        # Use initial RegEx match, then validate IP and return type
                        $_.Key
                    }
                } else {
                    # Return type
                    $_.Key
                }
            }
        }
    }
    end {
        if ($Output) {
            Write-Verbose "[Confirm-String] $($Output): $String"
            $Output
        }
    }
}
function Convert-Rfc3339 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [int] $Hours
    )
    process {
        # Return Rfc3339 timestamp for $Hours from Get-Date
        "$([Xml.XmlConvert]::ToString(
            (Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc) -replace '\.\d+Z$','Z')"
    }
}
function Get-ParamSet {
    [CmdletBinding()]
    param(
        [string] $Endpoint,
        [object] $Headers,
        [object] $Inputs,
        [object] $Format,
        [int] $Max
    )
    begin {
        # Get baseline switch and endpoint parameters
        $Switches = @{}
        if ($Inputs) {
            $Inputs.GetEnumerator().Where({ $_.Key -match '^(All|Detailed|Total)$' }).foreach{
                $Switches.Add($_.Key, $_.Value)
            }
        }
        $Base = @{
            Path    = "$($Script:Falcon.Hostname)$($Endpoint.Split(':')[0])"
            Method  = $Endpoint.Split(':')[1]
            Headers = $Headers
        }
        if (!$Max) {
            $IdCount = if ($Inputs.ids) {
                # Find maximum number of 'ids' using equivalent of 500 32-character ids
                [Math]::Floor([decimal](18500/(($Inputs.ids |
                    Measure-Object -Maximum -Property Length).Maximum + 5)))
            }
            $Max = if ($IdCount -and $IdCount -lt 500) {
                # Output maximum, no greater than 500
                $IdCount
            } else {
                500
            }
        }
        # Get 'Content' from user input
        $Content = Build-Content -Inputs $Inputs -Format $Format
    }
    process {
        if ($Content.Query -and ($Content.Query | Measure-Object).Count -gt $Max) {
            Write-Verbose "[Build-Param] Creating groups of $Max query values"
            for ($i = 0; $i -lt ($Content.Query | Measure-Object).Count; $i += $Max) {
                # Split 'Query' values into groups
                $Split = $Switches.Clone()
                $Split.Add('Endpoint', $Base.Clone())
                $Split.Endpoint.Path += "?$($Content.Query[$i..($i + ($Max - 1))] -join '&')"
                $Content.GetEnumerator().Where({ $_.Key -ne 'Query' -and $_.Value }).foreach{
                    # Add values other than 'Query'
                    $Split.Endpoint.Add($_.Key, $_.Value)
                }
                ,$Split
            }
        } elseif ($Content.Body -and ($Content.Body.ids | Measure-Object).Count -gt $Max) {
            Write-Verbose "[Build-Param] Creating groups of $Max 'ids'"
            for ($i = 0; $i -lt ($Content.Body.ids | Measure-Object).Count; $i += $Max) {
                # Split 'Body' content into groups using 'ids'
                $Split = $Switches.Clone()
                $Split.Add('Endpoint', $Base.Clone())
                $Split.Endpoint.Add('Body', @{ ids = $Content.Body.ids[$i..($i + ($Max - 1))] })
                $Content.GetEnumerator().Where({ $_.Value }).foreach{
                    # Add values other than 'Body.ids'
                    if ($_.Key -eq 'Query') {
                        $Split.Endpoint.Path += "?$($_.Value -join '&')"
                    } elseif ($_.Key -eq 'Body') {
                        ($_.Value).GetEnumerator().Where({ $_.Key -ne 'ids' }).foreach{
                            $Split.Endpoint.Body.Add($_.Key, $_.Value)
                        }
                    } else {
                        $Split.Endpoint.Add($_.Key, $_.Value)
                    }
                }
                ,$Split
            }
        } else {
            # Use base parameters, add content and output single parameter set
            $Switches.Add('Endpoint', $Base.Clone())
            if ($Content) {
                $Content.GetEnumerator().foreach{
                    if ($_.Key -eq 'Query') {
                        $Switches.Endpoint.Path += "?$($_.Value -join '&')"
                    } else {
                        $Switches.Endpoint.Add($_.Key, $_.Value)
                    }
                }
            }
            $Switches
        }
    }
}
function Get-RtrCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Command,
        [switch] $ConfirmCommand
    )
    process {
        # Determine command to invoke using $Command and permission level
        $Result = if ($Command -eq 'runscript') {
            # Force 'Admin' for 'runscript' command
            'Invoke-FalconAdminCommand'
        } else {
            # Create table of Real-time Response commands organized by permission level
            $Commands = @{}
            @($null, 'Responder', 'Admin').foreach{
                $Key = if ($_ -eq $null) {
                    'ReadOnly'
                } else {
                    $_
                }
                $Commands[$Key] = (Get-Command "Invoke-Falcon$($_)Command").Parameters.GetEnumerator().Where({
                    $_.Key -eq 'Command' }).Value.Attributes.ValidValues
            }
            # Filter 'Responder' and 'Admin' to unique command(s)
            $Commands.Responder = $Commands.Responder | Where-Object { $Commands.ReadOnly -notcontains $_ }
            $Commands.Admin = $Commands.Admin | Where-Object { $Commands.ReadOnly -notcontains $_ -and
                $Commands.Responder -notcontains $_ }
            $Commands.GetEnumerator().Where({ $_.Value -contains $Command }).foreach{
                if ($_.Key -eq 'ReadOnly') {
                    'Invoke-FalconCommand'
                } else {
                    "Invoke-Falcon$($_.Key)Command"
                }
            }
        }
    }
    end {
        if ($PSBoundParameters.ConfirmCommand) {
            # Output 'Confirm' command
            $Result -replace 'Invoke', 'Confirm'
        } else {
            $Result
        }
    }
}
function Get-RtrResult {
    [CmdletBinding()]
    param(
        [object] $Object,
        [object] $Output
    )
    begin {
        # Real-time Response fields to capture from results
        $RtrFields = @('aid', 'complete', 'errors', 'offline_queued', 'session_id', 'stderr', 'stdout', 'task_id')
    }
    process {
        # Update $Output with results from $Object
        foreach ($Result in ($Object | Select-Object $RtrFields)) {
            $Result.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object {
                $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
                    # Convert array result into string
                    $_.Value -join ', '
                } elseif ($_.Value.code -and $_.Value.message) {
                    # Convert error code and message into string
                    (($_.Value).foreach{ "$($_.code): $($_.message)" }) -join ', '
                } else {
                    $_.Value
                }
                $Name = if ($_.Name -eq 'task_id') {
                    # Rename 'task_id' to 'cloud_request_id'
                    'cloud_request_id'
                } else {
                    $_.Name
                }
                $Output | Where-Object { $_.aid -eq $Result.aid } | ForEach-Object {
                    $_.$Name = $Value
                }
            }
        }
    }
    end {
        return $Output
    }
}
function Invoke-Falcon {
    [CmdletBinding()]
    param(
        [string] $Command,
        [string] $Endpoint,
        [object] $Headers,
        [object] $Inputs,
        [object] $Format,
        [int] $Max
    )
    begin {
        # Gather parameters for 'Get-ParamSet'
        $GetParam = @{}
        $PSBoundParameters.GetEnumerator().Where({ $_.Key -ne 'Command' }).foreach{
            $GetParam.Add($_.Key, $_.Value)
        }
        if (!$GetParam.Headers) {
            $GetParam.Add('Headers', @{})
        }
        if (!$GetParam.Headers.Accept) {
            # Add 'Accept: application/json' when undefined
            $GetParam.Headers.Add('Accept', 'application/json')
        }
        if ($Format.Body -and !$GetParam.Headers.ContentType) {
            # Add 'ContentType: application/json' when undefined and 'Body' is present
            $GetParam.Headers.Add('ContentType', 'application/json')
        }
        if ($Inputs.All -eq $true -and !$Inputs.Limit) {
            # Add maximum 'Limit' when not present and using 'All'
            $Limit = (Get-Command $Command).ParameterSets.Where({
                $_.Name -eq $Endpoint }).Parameters.Where({ $_.Name -eq 'Limit' }).Attributes.MaxRange
            if ($Limit) {
                $Inputs.Add('Limit', $Limit)
            }
        }
        # Regex for URL paths that don't need a secondary 'Detailed' request
        [regex] $NoDetail = '(/combined/|/rule-groups-full/)'
    }
    process {
        foreach ($ParamSet in (Get-ParamSet @GetParam)) {
            try {
                if (!$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -or
                ($Script:Falcon.Expiration -le (Get-Date).AddSeconds(15))) {
                    # Verify authorization token
                    Request-FalconToken
                }
                if ((Test-FalconToken).Token -eq $false) {
                    # Stop if authorization token request fails
                    break
                }
                if ($ParamSet.Endpoint.Body -and $ParamSet.Endpoint.Headers.ContentType -eq 'application/json') {
                    # Convert body to Json
                    $ParamSet.Endpoint.Body = ConvertTo-Json -InputObject $ParamSet.Endpoint.Body -Depth 32
                }
                $Request = $Script:Falcon.Api.Invoke($ParamSet.Endpoint)
                if ($ParamSet.Endpoint.Outfile -and (Test-Path $ParamSet.Endpoint.Outfile)) {
                    # Display 'Outfile'
                    Get-ChildItem $ParamSet.Endpoint.Outfile
                } elseif ($Request.Result.Content) {
                    # Capture pagination for 'Total' and 'All'
                    $Pagination = (ConvertFrom-Json (
                        $Request.Result.Content).ReadAsStringAsync().Result).meta.pagination
                    if ($ParamSet.Total -eq $true -and $Pagination) {
                        # Output 'Total'
                        $Pagination.total
                    } else {
                        $Result = Write-Result $Request
                        if ($null -ne $Result) {
                            if ($ParamSet.Detailed -eq $true -and $ParamSet.Endpoint.Path -notmatch $NoDetail) {
                                # Output 'Detailed'
                                & $Command -Ids $Result
                            } else {
                                # Output result
                                $Result
                            }
                            if ($ParamSet.All -eq $true -and ($Result | Measure-Object).Count -lt
                            $Pagination.total) {
                                # Repeat requests
                                $Param = @{
                                    ParamSet   = $ParamSet
                                    Pagination = $Pagination
                                    Result     = $Result
                                }
                                Invoke-Loop @Param
                            }
                        }
                    }
                }
            } catch {
                Write-Error $_
            }
        }
    }
}
function Invoke-Loop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $ParamSet,

        [Parameter(Mandatory = $true)]
        [object] $Pagination,

        [Parameter(Mandatory = $true)]
        [object] $Result
    )
    begin {
        # Regex for URL paths that don't need a secondary 'Detailed' request
        [regex] $NoDetail = '(/combined/|/rule-groups-full/)'
    }
    process {
        for ($i = ($Result | Measure-Object).Count; $Pagination.next_page -or $i -lt $Pagination.total;
        $i += ($Result | Measure-Object).Count) {
            Write-Verbose "[Invoke-Loop] $i of $($Pagination.total)"
            # Clone endpoint parameters and update pagination
            $Clone = $ParamSet.Clone()
            $Clone.Endpoint = $ParamSet.Endpoint.Clone()
            $Page = if ($Pagination.after) {
                @('after', $Pagination.after)
            } elseif ($Pagination.next_page) {
                @('offset', $Pagination.offset)
            } elseif ($Pagination.offset -match '^\d{1,}$') {
                @('offset', $i)
            } else {
                @('offset', $Pagination.offset)
            }
            $Clone.Endpoint.Path = if ($Clone.Endpoint.Path -match "$($Page[0])=\d{1,}") {
                # If offset was input, continue from that value
                $Current = [regex]::Match($Clone.Endpoint.Path, 'offset=(\d+)(^&)?').Captures.Value
                $Page[1] += [int] $Current.Split('=')[-1]
                $Clone.Endpoint.Path -replace $Current, ($Page -join '=')
            } elseif ($Clone.Endpoint.Path -match "$Endpoint^") {
                # Add pagination
                "$($Clone.Endpoint.Path)?$($Page -join '=')"
            } else {
                "$($Clone.Endpoint.Path)&$($Page -join '=')"
            }
            # Make request, capture new pagination and output result
            $Request = $Script:Falcon.Api.Invoke($Clone.Endpoint)
            if ($Request.Result.Content) {
                $Result = Write-Result $Request
                if ($null -ne $Result) {
                    if ($Clone.Detailed -eq $true -and $Clone.Endpoint.Path -notmatch $NoDetail) {
                        & $Command -Ids $Result
                    } else {
                        $Result
                    }
                } else {
                    $ErrorMessage = ("[Invoke-Loop] Results limited by API " +
                        "'$(($Clone.Endpoint.Path).Split('?')[0] -replace $Script:Falcon.Hostname, $null)' " +
                        "($i of $($Pagination.total)).")
                    Write-Error $ErrorMessage
                }
                $Pagination = (ConvertFrom-Json (
                    $Request.Result.Content).ReadAsStringAsync().Result).meta.pagination
            }
        }
    }
}
function Update-FieldName {
    [CmdletBinding()]
    param(
        [object] $Fields,
        [object] $Inputs
    )
    process {
        # Update user input field names for API submission
        if ($Fields.Keys -and $Inputs.Keys) {
            ($Fields.Keys).foreach{
                if ($Inputs.$_ -or $Inputs.$_ -is [boolean]) {
                    $Inputs["$($Fields.$_)"] = $Inputs.$_
                    [void] $Inputs.Remove($_)
                }
            }
        }
        $Inputs
    }
}
function Write-Result {
    [CmdletBinding()]
    param (
        [object] $Request
    )
    begin {
        $Verbose = if ($Request.Result.Headers) {
            # Capture initial response header for verbose output
            ($Request.Result.Headers.GetEnumerator().foreach{
                ,"$($_.Key)=$($_.Value)"
            })
        }
    }
    process {
        if ($Request.Result.Content) {
            $Json = if ($Request.Result.Content.Headers.ContentType.MediaType -eq 'application/json' -or
            $Request.Result.Content.Headers.ContentType -eq 'application/json') {
                # Convert and capture Json content
                ConvertFrom-Json -InputObject ($Request.Result.Content).ReadAsStringAsync().Result
                if ($Json.meta) {
                    # Capture 'meta' values for verbose output
                    $Verbose += ($Json.meta.PSObject.Properties).foreach{
                        $Parent = 'meta'
                        if ($_.Value -is [PSCustomObject]) {
                            $Parent += ".$($_.Name)"
                            ($_.Value.PSObject.Properties).foreach{
                                ,"$($Parent).$($_.Name)=$($_.Value)"
                            }
                        } elseif ($_.Name -ne 'trace_id') {
                            ,"$($Parent).$($_.Name)=$($_.Value)"
                        }
                    }
                } elseif ($Json.extensions) {
                    # Capture 'extensions' values for verbose output
                    $Verbose += ($Json.extensions.PSObject.Properties).foreach{
                        $Parent = 'extensions'
                        if ($_.Value -is [PSCustomObject]) {
                            $Parent += ".$($_.Name)"
                            ($_.Value.PSObject.Properties).foreach{
                                ,"$($Parent).$($_.Name)=$($_.Value)"
                            }
                        } else {
                            ,"$($Parent).$($_.Name)=$($_.Value)"
                        }
                    }
                }
            }
            # Output response header and 'meta' or 'extensions' content
            Write-Verbose "[Write-Result] $($Verbose -join ', ')"
            if ($Json) {
                $ResultFields = ($Json.PSObject.Properties).Where({
                    $_.Name -notmatch '^(errors|extensions|meta)$' -and $_.Value
                }).foreach{
                    # Gather field names from result and exclude 'errors', 'extensions', and 'meta'
                    $_.Name
                }
                if ($ResultFields -and ($ResultFields | Measure-Object).Count -eq 1) {
                    if ($ResultFields[0] -eq 'combined' -and $Json.($ResultFields[0]).resources) {
                        # Output 'combined.resources'
                        $Json.($ResultFields[0]).resources.PSObject.Properties.Value
                    } else {
                        $Json.($ResultFields[0])
                    }
                } elseif ($ResultFields) {
                    # Export all fields
                    $Json | Select-Object $ResultFields
                } else {
                    # Output relevant 'meta' values
                    $MetaFields = ($Json.meta.PSObject.Properties).Where({
                        $_.Name -notmatch '^(entity|pagination|powered_by|query_time|trace_id)$'
                    }).foreach{
                        $_.Name
                    }
                    if ($MetaFields) {
                        $Json.meta | Select-Object $MetaFields
                    }
                }
                ($Json.PSObject.Properties).Where({ $_.Name -eq 'errors' -and $_.Value }).foreach{
                    ($_.Value).foreach{
                        # Output errors from Json response
                        $PSCmdlet.WriteError(
                            [System.Management.Automation.ErrorRecord]::New(
                                [Exception]::New("$($_.code): $($_.message)"),
                                $Json.meta.trace_id,
                                [System.Management.Automation.ErrorCategory]::NotSpecified,
                                $Request
                            )
                        )
                    }
                }
            } else {
                # Output Result.Content as [string]
                ($Request.Result.Content).ReadAsStringAsync().Result
            }
            # Check for rate limiting
            Wait-RetryAfter $Request
        }
    }
}
function Wait-RetryAfter {
    [CmdletBinding()]
    param(
        [object] $Request
    )
    process {
        if ($Request.Result.StatusCode -and $Request.Result.StatusCode.GetHashCode() -eq 429 -and
        $Request.Result.RequestMessage.RequestUri.AbsolutePath -ne '/oauth2/token') {
            # Convert 'X-Ratelimit-Retryafter' value to seconds and wait
            $Wait = [System.DateTimeOffset]::FromUnixTimeSeconds(($Request.Result.Headers.GetEnumerator().Where({
                $_.Key -eq 'X-Ratelimit-Retryafter' }).Value)).Second
            Write-Verbose "[Wait-RetryAfter] Rate limited for $Wait seconds..."
            Start-Sleep -Seconds $Wait
        }
    }
    end {
        if ($Request) {
            $Request.Dispose()
        }
    }
}