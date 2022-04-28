function Edit-FalconIoc {
<#
.SYNOPSIS
Modify custom indicators
.DESCRIPTION
Requires 'IOC Manager APIs: Write'.
.PARAMETER Action
Action to perform when a host observes the indicator
.PARAMETER Platform
Operating system platform
.PARAMETER Source
Origination source
.PARAMETER Severity
Severity level
.PARAMETER Description
Indicator description
.PARAMETER Filename
Indicator filename,used with hash values
.PARAMETER Tag
Indicator tag
.PARAMETER HostGroup
Host group identifier
.PARAMETER AppliedGlobally
Assign to all host groups
.PARAMETER Expiration
Expiration date. When an indicator expires, its action is set to 'no_action' but it remains in your indicator list.
.PARAMETER Comment
Audit log comment
.PARAMETER Retrodetect
Generate retroactive detections for hosts that have observed the indicator
.PARAMETER IgnoreWarning
Ignore warnings and modify all indicators
.PARAMETER Id
Indicator identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/iocs/entities/indicators/v1:patch')]
    param(
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=1)]
        [ValidateSet('no_action','allow','prevent_no_ui','detect','prevent',IgnoreCase=$false)]
        [string]$Action,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidateSet('linux','mac','windows',IgnoreCase=$false)]
        [Alias('Platforms')]
        [string[]]$Platform,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidateRange(1,256)]
        [string]$Source,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=4)]
        [ValidateSet('informational','low','medium','high','critical',IgnoreCase=$false)]
        [string]$Severity,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=5)]
        [string]$Description,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=6)]
        [Alias('metadata.filename')]
        [string]$Filename,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=7)]
        [Alias('tags')]
        [string[]]$Tag,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=8)]
        [ValidatePattern('^\w{32}$')]
        [Alias('host_groups','HostGroups')]
        [string[]]$HostGroup,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=9)]
        [Alias('applied_globally')]
        [boolean]$AppliedGlobally,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=10)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$')]
        [string]$Expiration,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',ValueFromPipelineByPropertyName,
            Position=11)]
        [string]$Comment,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',Position=12)]
        [Alias('retrodetects')]
        [boolean]$Retrodetect,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',Position=13)]
        [Alias('ignore_warnings','IgnoreWarnings')]
        [boolean]$IgnoreWarning,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=14)]
        [ValidatePattern('^\w{64}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('retrodetects','ignore_warnings')
                Body = @{
                    root = @('comment')
                    indicators = @('id','tags','applied_globally','expiration','description',
                        'metadata.filename','source','host_groups','severity','action','platforms')
                }
            }
        }
    }
    process {
        if (!$PSBoundParameters.HostGroup -and !$PSBoundParameters.AppliedGlobally) {
            throw "'HostGroup' or 'AppliedGlobally' must be provided."
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconIoc {
<#
.SYNOPSIS
Search for custom indicators
.DESCRIPTION
Requires 'IOC Manager APIs: Read'.
.PARAMETER Id
Indicator identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/iocs/queries/indicators/v1:get')]
    param(
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{64}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get',Position=1)]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get',Position=2)]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get',Position=2)]
        [ValidateSet('action.asc','action.desc','applied_globally.asc','applied_globally.desc',
            'metadata.av_hits.asc','metadata.av_hits.desc','metadata.company_name.raw.asc',
            'metadata.company_name.raw.desc','created_by.asc','created_by.desc','created_on.asc',
            'created_on.desc','expiration.asc','expiration.desc','expired.asc','expired.desc',
            'metadata.filename.raw.asc','metadata.filename.raw.desc','modified_by.asc','modified_by.desc',
            'modified_on.asc','modified_on.desc','metadata.original_filename.raw.asc',
            'metadata.original_filename.raw.desc','metadata.product_name.raw.asc',
            'metadata.product_name.raw.desc','metadata.product_version.asc','metadata.product_version.desc',
            'severity_number.asc','severity_number.desc','source.asc','source.desc','type.asc','type.desc',
            'value.asc','value.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get',Position=3)]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get',Position=3)]
        [ValidateRange(1,2000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get')]
        [string]$After,
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/iocs/combined/indicator/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/iocs/queries/indicators/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','filter','offset','limit','sort','after') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function New-FalconIoc {
<#
.SYNOPSIS
Create custom indicators
.DESCRIPTION
Requires 'IOC Manager APIs: Write'.
.PARAMETER Array
An array of indicators to create in a single request
.PARAMETER Type
Indicator type
.PARAMETER Value
String representation of the indicator
.PARAMETER Action
Action to perform when a host observes the indicator
.PARAMETER Platform
Operating system platform
.PARAMETER Source
Origination source
.PARAMETER Severity
Severity level
.PARAMETER Description
Indicator description
.PARAMETER Filename
Indicator filename,used with hash values
.PARAMETER Tag
Indicator tag
.PARAMETER HostGroup
Host group identifier
.PARAMETER AppliedGlobally
Assign to all host groups
.PARAMETER Expiration
Expiration date. When an indicator expires,its action is set to 'no_action' but it remains in your indicator list.
.PARAMETER Comment
Audit log comment
.PARAMETER Retrodetect
Generate retroactive detections for hosts that have observed the indicator
.PARAMETER IgnoreWarning
Ignore warnings and create all indicators
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/iocs/entities/indicators/v1:post')]
    param(
        [Parameter(ParameterSetName='array',Mandatory,ValueFromPipeline)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'New-FalconIoc'
                    Endpoint = '/iocs/entities/indicators/v1:post'
                    Required = @('type','value','action','platforms')
                    Content = @('action','platforms','severity','type')
                    Pattern = @('expiration','host_groups')
                    Format = @{ host_groups = 'HostGroup' }
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('indicators')]
        [object[]]$Array,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Mandatory,Position=1)]
        [ValidateSet('no_action','allow','prevent_no_ui','detect','prevent',IgnoreCase=$false)]
        [string]$Action,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Mandatory,Position=2)]
        [ValidateSet('linux','mac','windows',IgnoreCase=$false)]
        [Alias('platforms')]
        [string[]]$Platform,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=3)]
        [ValidateRange(1,256)]
        [string]$Source,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=4)]
        [ValidateSet('informational','low','medium','high','critical',IgnoreCase=$false)]
        [string]$Severity,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=5)]
        [string]$Description,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=6)]
        [Alias('metadata.filename')]
        [string]$Filename,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=7)]
        [Alias('tags')]
        [string[]]$Tag,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=8)]
        [ValidatePattern('^\w{32}$')]
        [Alias('host_groups','HostGroups')]
        [string[]]$HostGroup,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=9)]
        [Alias('applied_globally')]
        [boolean]$AppliedGlobally,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=10)]
        [ValidatePattern('^(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$')]
        [string]$Expiration,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=11)]
        [Parameter(ParameterSetName='array',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=12)]
        [Parameter(ParameterSetName='array',Position=3)]
        [Alias('Retrodetects')]
        [boolean]$Retrodetect,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Position=13)]
        [Parameter(ParameterSetName='array',Position=4)]
        [Alias('ignore_warnings','IgnoreWarnings')]
        [boolean]$IgnoreWarning,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Mandatory,Position=14)]
        [ValidateSet('domain','ipv4','ipv6','md5','sha256',IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:post',Mandatory,Position=15)]
        [Alias('indicator')]
        [string]$Value
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/iocs/entities/indicators/v1:post'
            Format = @{
                Query = @('retrodetects','ignore_warnings')
                Body = @{
                    root = @('comment','indicators')
                    indicators = @('tags','applied_globally','expiration','description','value',
                        'metadata.filename','type','source','host_groups','severity','action','platforms')
                }
            }
        }
        [System.Collections.Generic.List[object]]$List = @()
    }
    process {
        if ($Array) {
            @($Array).foreach{ $List.Add($_) }
        } elseif (!$PSBoundParameters.HostGroup -and !$PSBoundParameters.AppliedGlobally) {
            throw "'HostGroup' or 'AppliedGlobally' must be provided."
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            for ($i = 0; $i -lt $List.Count; $i += 100) {
                $PSBoundParameters['Array'] = @($List[$i..($i + 99)])
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Remove-FalconIoc {
<#
.SYNOPSIS
Remove custom indicators
.DESCRIPTION
Requires 'IOC Manager APIs: Write'.
.PARAMETER Filter
Falcon Query Language expression to find indicators for removal
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Indicator identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding(DefaultParameterSetName='/iocs/entities/indicators/v1:delete')]
    param(
        [Parameter(ParameterSetName='Filter',Mandatory)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:delete',Position=1)]
        [Parameter(ParameterSetName='Filter',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/iocs/entities/indicators/v1:delete',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{64}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/iocs/entities/indicators/v1:delete'
            Format = @{ Query = @('ids','filter','comment') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } elseif ($Filter) {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if (!$Id -and !$Filter) {
            throw "'Filter' or 'Id' must be provided."
        } elseif ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}