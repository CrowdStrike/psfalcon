function Get-FalconMalQuery {
<#
.Synopsis
Check the status and results of an asynchronous request, such as hunt or exact-search
.Parameter Ids
MalQuery request identifier(s)
.Role
malquery:read
.Example
PS>Get-FalconMalQuery -Ids <id>, <id>

Return detailed status of MalQuery request <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/requests/v1:get')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/requests/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconMalQueryQuota {
<#
.Synopsis
List your Falcon MalQuery search and download quota
.Role
malquery:read
.Example
PS>Get-FalconMalQueryQuota

Return MalQuery search and download quota information.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/aggregates/quotas/v1:get')]
    param()
    begin {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/malquery/aggregates/quotas/v1"
            Method  = 'get'
            Headers = @{
                Accept = 'application/json'
            }
        }
    }
    process {
        $Request = $Script:Falcon.Api.Invoke($Param)
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta
        } else {
            throw "Unable to retrieve MalQuery quota. Check client permissions."
        }
    }
}
function Get-FalconMalQuerySample {
<#
.Synopsis
Retrieve Falcon MalQuery indexed file metadata by Sha256 hash
.Parameter Ids
Sha256 hash value(s)
.Role
malquery:read
.Example
PS>Get-FalconMalQuerySample -Ids <id>, <id>

Retrieve detailed information about MalQuery samples <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/metadata/v1:get')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/metadata/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Group-FalconMalQuerySample {
<#
.Synopsis
Schedule MalQuery samples for download
.Parameter Samples
Sha256 hash value(s)
.Role
malquery:write
.Example
PS>$Request = Group-FalconMalQuerySample -Samples <sha256>, <sha256>

Request an archive of MalQuery samples <sha256> and <sha256>. 'Get-FalconMalQuery' can be used to check the
status of the request contained in the variable '$Request', and 'Receive-FalconMalQuerySample' can be used to
download the archive once the request is complete.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/samples-multidownload/v1:post')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/samples-multidownload/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Samples
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('samples')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconMalQuery {
<#
.Synopsis
Search Falcon MalQuery using a YARA hunt, exact search or fuzzy search
.Parameter YaraRule
Schedule a YARA-based search for execution
.Parameter Type
Search pattern type
.Parameter Value
Search pattern value
.Parameter FilterFiletypes
File type(s) to include with the result
.Parameter FilterMeta
Subset of metadata fields to include in the result
.Parameter MinSize
Minimum file size specified in bytes or multiples of KB/MB/GB
.Parameter MaxSize
Maximum file size specified in bytes or multiples of KB/MB/GB
.Parameter MinDate
Limit results to files first seen after this date
.Parameter MaxDate
Limit results to files first seen before this date
.Parameter Limit
Maximum number of results per request
.Parameter Fuzzy
Search MalQuery quickly but with more potential for false positives
.Parameter Detailed
Retrieve detailed information
.Role
malquery:write
.Example
PS>Invoke-FalconMalQuery -FilterFiletypes pe32 -MaxSize 1200KB -FilterMeta sha256, label, family -YaraRule "
    rule CrowdStrike_16142_01 : wiper { strings: $ = { 41 61 43 63 64 44 65 46 66 47 68 69 4B 4C 6C 4D 6D 6E 4E
    6F 4F 70 50 72 52 73 53 54 74 55 75 56 76 77 57 78 79 5A 7A 33 32 2E 5C 45 62 67 6A 48 49 20 5F 59 51 42 3A
    22 2F 40 } condition: all of them and filesize < 800KB }"

Perform a MalQuery YARA Hunt for a hex value and return 'sha256', 'label' and 'family' for PE32 files under
1,200KB.
.Example
PS>Invoke-FalconMalQuery -FilterMeta sha256, type, size -FilterFiletypes pe32, pe64 -MaxSize 1200KB -MinDate
    2017/01/01 -Limit 20 -Type hex -Value 8948208b480833ca33f989502489482889782c8bd7

Perform a MalQuery exact search for a hex value and return 'sha256', 'type' and 'size' for a maximum of 20 PE32
and PE64 files under 1,200KB, created after 2017/01/01.
.Example
PS>Invoke-FalconMalQuery -Limit 3 -Type ascii -Value ".8@bVn7r&k" -Fuzzy

Perform a MalQuery fuzzy search for a string value and return the first 3 results.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/queries/exact-search/v1:post')]
    param(
        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Mandatory = $true, Position = 1)]
        [string] $YaraRule,

        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('hex', 'ascii', 'wide')]
        [string] $Type,

        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Mandatory = $true, Position = 2)]
        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post', Mandatory = $true, Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 2)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 3)]
        [ValidateSet('cdf', 'cdfv2', 'cjava', 'dalvik', 'doc', 'docx', 'elf32', 'elf64', 'email', 'html', 'hwp',
            'java.arc', 'lnk', 'macho', 'pcap', 'pdf', 'pe32', 'pe64', 'perl', 'ppt', 'pptx', 'python', 'pythonc',
            'rtf', 'swf', 'text', 'xls', 'xlsx')]
        [array] $FilterFiletypes,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 3)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 4)]
        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post', Position = 3)]
        [ValidateSet('sha256', 'md5', 'type', 'size', 'first_seen', 'label', 'family')]
        [array] $FilterMeta,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 4)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 5)]
        [string] $MinSize,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 5)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 6)]
        [string] $MaxSize,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 6)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 7)]
        [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
        [string] $MinDate,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 7)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 8)]
        [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
        [string] $MaxDate,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Position = 8)]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post', Position = 9)]
        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post', Position = 4)]
        [int32] $Limit,

        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post', Mandatory = $true)]
        [switch] $Fuzzy,

        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post')]
        [Parameter(ParameterSetName = '/malquery/queries/exact-search/v1:post')]
        [Parameter(ParameterSetName = '/malquery/combined/fuzzy-search/v1:post')]
        [switch] $Detailed
    )
    begin {
        $Fields = @{
            FilterFiletypes = 'filter_filetypes'
            FilterMeta      = 'filter_meta'
            MaxDate         = 'max_date'
            MinDate         = 'min_date'
            MaxSize         = 'max_size'
            MinSize         = 'min_size'
            YaraRule        = 'yara_rule'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('yara_rule')
                    options = @('min_size', 'limit', 'filter_filetypes', 'min_date', 'filter_meta',
                        'max_date', 'max_size')
                    patterns = @('type', 'value')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconMalQuerySample {
<#
.Synopsis
Download a sample or sample archive from Falcon MalQuery [password: 'infected']
.Parameter Id
Sha256 hash value or MalQuery sample archive identifier
.Parameter Path
Destination path
.Role
malquery:read
.Example
PS>Receive-FalconMalQuerySample -Id $Request.reqid -Path infected.zip

Download the archive previously requested and saved to the variable '$Request' by 'Group-FalconMalQuerySample' as
'infected.zip' in your local directory.
.Example
PS>Receive-FalconMalQuerySample -Id <sha256> -Path infected.exe

Download MalQuery sample <sha256> as 'infected.exe' in your local directory.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/download-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/download-files/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^(\w{64}|\w{8}-\w{4}-\w{4}-\w{4}-\w{12})$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/malquery/entities/download-files/v1:get', Mandatory = $true, Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        if ($PSBoundParameters.Id -match '^\w{64}$') {
            $Accept = 'application/octet-stream'
            $Endpoint = '/malquery/entities/download-files/v1:get'
        } else {
            $Accept = 'application/zip'
            $Endpoint = '/malquery/entities/samples-fetch/v1:get'
        }
        $Fields = @{
            Id = 'ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $Endpoint
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                Accept = $Accept
            }
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Search-FalconMalQueryHash {
<#
.Synopsis
Perform a simple MalQuery YARA Hunt for a Sha256 hash
.Description
Performs a YARA Hunt for the given hash, then checks every 5 seconds--for up to 30 seconds--for a result.
.Parameter Sha256
Sha256 hash value
.Role
malquery:write
.Example
PS>Search-FalconMalQueryHash -Sha256 <sha256>

Perform a YARA Hunt in MalQuery for the SHA256 hash value <sha256>.
#>
    [CmdletBinding(DefaultParameterSetName = '/malquery/queries/hunt/v1:post')]
    param(
        [Parameter(ParameterSetName = '/malquery/queries/hunt/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Sha256
    )
    begin {
        $Sleep = 5
        $MaxSleep = 30
    }
    process {
        try {
            $Param = @{
                YaraRule = "import `"hash`"`nrule SearchHash`n{`ncondition:`nhash.sha256(0, filesize) == " +
                "`"$($PSBoundParameters.Sha256)`"`n}"
                FilterMeta = 'sha256', 'type', 'label', 'family'
            }
            $Request = Invoke-FalconMalQuery @Param
            if ($Request.reqid) {
                $Param = @{
                    Ids = $Request.reqid
                    OutVariable = 'Result'
                }
                if ((Get-FalconMalQuery @Param).status -eq 'inprogress') {
                    do {
                        Start-Sleep -Seconds $Sleep
                        $i += $Sleep
                    } until (
                        ((Get-FalconMalQuery @Param).status -ne 'inprogress') -or ($i -ge $MaxSleep)
                    )
                }
                $Result
            }
        } catch {
            $_
        }
    }
}