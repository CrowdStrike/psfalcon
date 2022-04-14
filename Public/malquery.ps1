function Get-FalconMalQuery {
<#
.SYNOPSIS
Verify the status and results of an asynchronous Falcon MalQuery request,such as a hunt or exact-search
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Id
Request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/entities/requests/v1:get')]
    param(
        [Parameter(ParameterSetName='/malquery/entities/requests/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconMalQueryQuota {
<#
.SYNOPSIS
Retrieve Falcon MalQuery search and download quotas
.DESCRIPTION
Requires 'MalQuery: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/aggregates/quotas/v1:get')]
    param()
    process {
        $Request = Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName -RawOutput -EA 0
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta
        } else {
            throw "Unable to retrieve MalQuery quota. Check client permissions."
        }
    }
}
function Get-FalconMalQuerySample {
<#
.SYNOPSIS
Retrieve Falcon MalQuery indexed file metadata
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/entities/metadata/v1:get')]
    param(
        [Parameter(ParameterSetName='/malquery/entities/metadata/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{64}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Group-FalconMalQuerySample {
<#
.SYNOPSIS
Schedule MalQuery samples for download
.DESCRIPTION
Requires 'MalQuery: Write'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/entities/samples-multidownload/v1:post')]
    param(
        [Parameter(ParameterSetName='/malquery/entities/samples-multidownload/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{64}$')]
        [Alias('samples','sample','ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('samples') }}
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Invoke-FalconMalQuery {
<#
.SYNOPSIS
Initiate a Falcon MalQuery YARA hunt,exact search or fuzzy search
.DESCRIPTION
Requires 'MalQuery: Write'.
.PARAMETER YaraRule
Schedule a YARA-based search
.PARAMETER Type
Search pattern type
.PARAMETER Value
Search pattern value
.PARAMETER FilterFiletype
File type to include with the result
.PARAMETER FilterMeta
Subset of metadata fields to include in the result
.PARAMETER MinSize
Minimum file size specified in bytes or multiples of KB/MB/GB
.PARAMETER MaxSize
Maximum file size specified in bytes or multiples of KB/MB/GB
.PARAMETER MinDate
Limit results to files first seen after this date
.PARAMETER MaxDate
Limit results to files first seen before this date
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Fuzzy
Search MalQuery quickly but with more potential for false positives
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/queries/exact-search/v1:post')]
    param(
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Mandatory,Position=1)]
        [Alias('yara_rule')]
        [string]$YaraRule,
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory,Position=1)]
        [ValidateSet('hex','ascii','wide',IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Mandatory,Position=2)]
        [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory,Position=2)]
        [string]$Value,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=2)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=3)]
        [ValidateSet('cdf','cdfv2','cjava','dalvik','doc','docx','elf32','elf64','email','html','hwp',
            'java.arc','lnk','macho','pcap','pdf','pe32','pe64','perl','ppt','pptx','python','pythonc',
            'rtf','swf','text','xls','xlsx',IgnoreCase=$false)]
        [Alias('filter_filetypes','FilterFileTypes')]
        [string[]]$FilterFiletype,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=3)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=4)]
        [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Position=3)]
        [ValidateSet('sha256','md5','type','size','first_seen','label','family',IgnoreCase=$false)]
        [Alias('filter_meta')]
        [string[]]$FilterMeta,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=4)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=5)]
        [Alias('min_size')]
        [string]$MinSize,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=5)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=6)]
        [Alias('max_size')]
        [string]$MaxSize,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=6)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=7)]
        [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
        [Alias('min_date')]
        [string]$MinDate,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=7)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=8)]
        [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
        [Alias('max_date')]
        [string]$MaxDate,
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=8)]
        [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=9)]
        [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Position=4)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory)]
        [switch]$Fuzzy
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('yara_rule','options')
                    patterns = @('type','value')
                }
            }
        }
        $Aliases = (Get-Command $MyInvocation.MyCommand.Name).Parameters.GetEnumerator().Where({
            $_.Value.Attributes.ParameterSetName -eq $PSCmdlet.ParameterSetName })
        $Options = @{}
        foreach ($Opt in @('FilterFiletype','FilterMeta','Limit','MaxDate','MaxSize','MinDate','MinSize')) {
            if ($PSBoundParameters.$Opt) {
                $Alias = $Aliases.Where({ $_.Key -eq $Opt }).Value.Aliases[0]
                $Key = if ($Alias) { $Alias } else { $Opt.ToLower() }
                $Options[$Key] = $PSBoundParameters.$Opt
                [void]$PSBoundParameters.Remove($Opt)
            }
        }
        if ($Options) { $PSBoundParameters['options'] = $Options }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Receive-FalconMalQuerySample {
<#
.SYNOPSIS
Download a sample or sample archive from Falcon MalQuery [password: 'infected']
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Sha256 hash value or MalQuery sample archive identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/entities/download-files/v1:get')]
    param(
        [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get',Mandatory,Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^(\w{64}|\w{8}-\w{4}-\w{4}-\w{4}-\w{12})$')]
        [Alias('ids')]
        [string]$Id,
        [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = if ($PSBoundParameters.Id -match '^\w{64}$') {
                '/malquery/entities/download-files/v1:get'
            } else {
                '/malquery/entities/samples-fetch/v1:get'
            }
            Headers = if ($PSBoundParameters.Id -match '^\w{64}$') {
                @{ Accept = 'application/octet-stream' }
            } else {
                @{ Accept = 'application/zip' }
            }
            Format = @{ Query = @('ids') }
        }
    }
    process {
        if ($Param.Headers.Accept -match 'zip$') {
            $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'zip'
        }
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Search-FalconMalQueryHash {
<#
.SYNOPSIS
Perform a simple Falcon MalQuery YARA Hunt for a Sha256 hash
.DESCRIPTION
Requires 'MalQuery: Write'.

Performs a YARA Hunt for the given hash,then checks every 5 seconds--for up to 30 seconds--for a result.
.PARAMETER Sha256
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/MalQuery
#>
    [CmdletBinding(DefaultParameterSetName='/malquery/queries/hunt/v1:post')]
    param(
        [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{64}$')]
        [string]$Sha256
    )
    process {
        try {
            $Param = @{
                YaraRule = 'import "hash" rule SearchHash { condition: hash.sha256(0,filesize) == "' +
                    $PSBoundParameters.Sha256 + '" }'
                FilterMeta = @('sha256','type','label','family')
            }
            $Request = Invoke-FalconMalQuery @Param
            if ($Request.reqid) {
                $Result = Get-FalconMalQuery -Id $Request.reqid
                if ($Result.status -eq 'inprogress') {
                    do {
                        Start-Sleep -Seconds 5
                        $i += 5
                        $Result = Get-FalconMalQuery -Id $Request.reqid
                    } until (
                        ($Result.status -ne 'inprogress') -or ($i -ge 30)
                    )
                }
                $Result
            }
        } catch {
            $_
        }
    }
}