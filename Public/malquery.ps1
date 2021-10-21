function Get-FalconMalQuery {
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/requests/v1:get')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/requests/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconMalQueryQuota {
    [CmdletBinding(DefaultParameterSetName = '/malquery/aggregates/quotas/v1:get')]
    param()
    process {
        $Request = Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName -RawOutput
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta
        } else {
            throw "Unable to retrieve MalQuery quota. Check client permissions."
        }
    }
}
function Get-FalconMalQuerySample {
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/metadata/v1:get')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/metadata/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Group-FalconMalQuerySample {
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/samples-multidownload/v1:post')]
    param(
        [Parameter(ParameterSetName = '/malquery/entities/samples-multidownload/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Samples
    )
    process {
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
        Invoke-Falcon @Param
    }
}
function Invoke-FalconMalQuery {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Receive-FalconMalQuerySample {
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
        $Fields = @{
            Id = 'ids'
        }
    }
    process {
        if ($PSBoundParameters.Id -match '^\w{64}$') {
            $Accept = 'application/octet-stream'
            $Endpoint = '/malquery/entities/download-files/v1:get'
        } else {
            $Accept = 'application/zip'
            $Endpoint = '/malquery/entities/samples-fetch/v1:get'
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
        Invoke-Falcon @Param
    }
}
function Search-FalconMalQueryHash {
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