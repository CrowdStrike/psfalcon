function Get-FalconMalQuery {
<#
.Synopsis
Check the status and results of an asynchronous request, such as hunt or exact-search
.Parameter Ids
MalQuery request identifier(s)
.Role
malquery:read
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
#>
    [CmdletBinding()]
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
Schedule samples for download
.Parameter Samples
Sha256 hash value(s)
.Role
malquery:write
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