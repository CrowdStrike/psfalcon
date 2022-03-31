function Edit-FalconReconAction {
<#
.SYNOPSIS
Modify a Falcon X Recon action
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Frequency
Action frequency
.PARAMETER Recipient
Email address
.PARAMETER Status
Action status
.PARAMETER Id
Action identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/actions/v1:patch')]
    param(
        [Parameter(ParameterSetName='/recon/entities/actions/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=1)]
        [ValidateSet('asap','daily','weekly',IgnoreCase=$false)]
        [string]$Frequency,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('Recipients')]
        [string[]]$Recipient,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidateSet('enabled','muted',IgnoreCase=$false)]
        [string]$Status,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id

    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('recipients','id','status','frequency') }}
        }
        [System.Collections.ArrayList] $EmailArray = @()
    }
    process {
        if ($Recipient) {
            @($Recipient).foreach{ [void] $EmailArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($EmailArray) {
            $PSBoundParameters['Recipient'] = @($EmailArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Edit-FalconReconNotification {
<#
.SYNOPSIS
Modify a Falcon X Recon notification
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Array
An array of notifications to modify in a single request
.PARAMETER Status
Notification status
.PARAMETER AssignedToUuid
User identifier
.PARAMETER Id
Notification identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/notifications/v1:patch')]
    param(
        [Parameter(ParameterSetName='array',Mandatory)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'Edit-FalconReconNotification'
                    Endpoint = '/recon/entities/notifications/v1:patch'
                    Required = @('id','assigned_to_uuid','status')
                    Pattern = @('id','assigned_to_uuid')
                    Format = @{ assigned_to_uuid = 'AssignedToUuid' }
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [array]$Array,

        [Parameter(ParameterSetName='/recon/entities/notifications/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Status,

        [Parameter(ParameterSetName='/recon/entities/notifications/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('assigned_to_uuid')]
        [string]$AssignedToUuid,

        [Parameter(ParameterSetName='/recon/entities/notifications/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{76}$')]
        [string]$Id
    )
    begin {
        if ($PSBoundParameters.Array) {
            if (!$Script:Falcon.Hostname) { Request-FalconToken }
            $Param = @{
                Path = "$($Script:Falcon.Hostname)/recon/entities/notifications/v1"
                Method = 'patch'
                Headers = @{
                    Accept = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Edit notifications in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @($Group) -Depth 8
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request
            }
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Format = @{ Body = @{ root = @('assigned_to_uuid','id','status') }}
            }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Edit-FalconReconRule {
<#
.SYNOPSIS
Modify a Falcon X Recon monitoring rule
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Array
An array of monitoring rules to modify in a single request
.PARAMETER Name
Monitoring rule name
.PARAMETER Filter
Monitoring rule filter
.PARAMETER Priority
Monitoring rule priority
.PARAMETER Permission
Permission level [public: 'All Intel users', private: 'Recon Admins']
.PARAMETER Id
Monitoring rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/rules/v1:patch')]
    param(
        [Parameter(ParameterSetName='array',Mandatory)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'Edit-FalconReconRule'
                    Endpoint = '/recon/entities/rules/v1:patch'
                    Required = @('id','name','filter','priority','permissions')
                    Content = @('permissions','priority')
                    Pattern = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [array]$Array,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:patch',Mandatory,Position=1)]
        [string]$Name,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:patch',Mandatory,Position=2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:patch',Mandatory,Position=3)]
        [ValidateSet('high','medium','low',IgnoreCase=$false)]
        [string]$Priority,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:patch',Mandatory,Position=4)]
        [ValidateSet('private','public',IgnoreCase=$false)]
        [Alias('permissions')]
        [string]$Permission,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id
    )
    process {
        if ($PSBoundParameters.Array) {
            if (!$Script:Falcon.Hostname) { Request-FalconToken }
            $Param = @{
                Path = "$($Script:Falcon.Hostname)/recon/entities/rules/v1"
                Method = 'patch'
                Headers = @{
                    Accept = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Edit rules in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @($Group) -Depth 8
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request
            }
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Format = @{ Body = @{ root = @('permissions','priority','name','id','filter') }}
            }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconReconAction {
<#
.SYNOPSIS
Search for Falcon X Recon actions
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Read'.
.PARAMETER Id
Action identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/queries/actions/v1:get')]
    param(
        [Parameter(ParameterSetName='/recon/entities/actions/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get',Position=3)]
        [string]$Sort,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get',Position=4)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get',Position=5)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get')]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/recon/queries/actions/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','sort','q','offset','filter') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconReconNotification {
<#
.SYNOPSIS
Search for Falcon X Recon notifications
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Read'.
.PARAMETER Id
Notification identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.PARAMETER Intel
Include raw intelligence content
.PARAMETER Translate
Translate to English
.PARAMETER Combined
Include raw intelligence content and translate to English
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/queries/notifications/v1:get')]
    param(
        [Parameter(ParameterSetName='/recon/entities/notifications/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/recon/entities/notifications-detailed/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/recon/entities/notifications-translated/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/recon/entities/notifications-detailed-translated/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{76}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get',Position=3)]
        [ValidateSet('created_date|asc','created_date|desc','updated_date|asc','updated_date|desc',
            IgnoreCase=$false)]
        [string]$Sort,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get',Position=5)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get')]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/recon/queries/notifications/v1:get')]
        [switch]$Total,

        [Parameter(ParameterSetName='/recon/entities/notifications-detailed/v1:get',Mandatory)]
        [switch]$Intel,

        [Parameter(ParameterSetName='/recon/entities/notifications-translated/v1:get',Mandatory)]
        [switch]$Translate,

        [Parameter(ParameterSetName='/recon/entities/notifications-detailed-translated/v1:get',Mandatory)]
        [switch]$Combined
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','sort','q','offset','filter') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconReconRule {
<#
.SYNOPSIS
Search for Falcon X Recon monitoring rules
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Read'.
.PARAMETER Id
Monitoring rule identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName='/recon/entities/rules/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get',Position=3)]
        [ValidateSet('created_timestamp|asc','created_timestamp|desc','last_updated_timestamp|asc',
            'last_updated_timestamp|desc',IgnoreCase=$false)]
        [string]$Sort,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get',Position=5)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get')]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/recon/queries/rules/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','q','sort','offset','filter') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconReconRulePreview {
<#
.SYNOPSIS
Preview Falcon X Recon monitoring rule notification count and distribution
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Read'.
.PARAMETER Topic
Monitoring rule topic
.PARAMETER Filter
Monitoring rule filter
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/aggregates/rules-preview/GET/v1:post')]
    param(
        [Parameter(ParameterSetName='/recon/aggregates/rules-preview/GET/v1:post',Mandatory,Position=1)]
        [string]$Topic,

        [Parameter(ParameterSetName='/recon/aggregates/rules-preview/GET/v1:post',Mandatory,Position=2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('filter','topic') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function New-FalconReconAction {
<#
.SYNOPSIS
Create Falcon X Recon monitoring rule actions
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER RuleId
Monitoring rule identifier
.PARAMETER Type
Notification type
.PARAMETER Frequency
Notification frequency
.PARAMETER Recipient
Notification recipient
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/actions/v1:post')]
    param(
        [Parameter(ParameterSetName='/recon/entities/actions/v1:post',Mandatory,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('rule_id')]
        [string]$RuleId,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:post',Mandatory,Position=2)]
        [ValidateSet('email',IgnoreCase=$false)]
        [string]$Type,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:post',Mandatory,Position=3)]
        [ValidateSet('asap','daily','weekly',IgnoreCase=$false)]
        [string]$Frequency,

        [Parameter(ParameterSetName='/recon/entities/actions/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=4)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('recipients','uid')]
        [string[]]$Recipient
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('rule_id')
                    actions = @('recipients','type','frequency')
                }
            }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Recipient) { @($Recipient).foreach{ [void]$IdArray.Add($_) }}
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Recipient'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function New-FalconReconRule {
<#
.SYNOPSIS
Create Falcon X Recon monitoring rules
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Array
An array of monitoring rules to create in a single request
.PARAMETER Name
Monitoring rule name
.PARAMETER Topic
Monitoring rule topic
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Priority
Monitoring rule priority
.PARAMETER Permission
Permission level [public: 'All Intel users', private: 'Recon Admins']
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/rules/v1:post')]
    param(
        [Parameter(ParameterSetName='array',Mandatory)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'New-FalconReconRule'
                    Endpoint = '/recon/entities/rules/v1:post'
                    Required = @('name','topic','filter','priority','permissions')
                    Content = @('permissions','priority','topic')
                }
                Confirm-Parameter @Param
            }
        })]
        [array]$Array,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:post',Mandatory,Position=1)]
        [string]$Name,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:post',Mandatory,Position=2)]
        [ValidateSet('SA_ALIAS','SA_AUTHOR','SA_BIN','SA_BRAND_PRODUCT','SA_CUSTOM','SA_CVE','SA_DOMAIN',
            'SA_EMAIL','SA_IP','SA_THIRD_PARTY','SA_VIP',IgnoreCase=$false)]
        [string]$Topic,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:post',Mandatory,Position=3)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:post',Mandatory,Position=4)]
        [ValidateSet('high','medium','low',IgnoreCase=$false)]
        [string]$Priority,

        [Parameter(ParameterSetName='/recon/entities/rules/v1:post',Mandatory,Position=5)]
        [ValidateSet('private','public',IgnoreCase=$false)]
        [Alias('permissions')]
        [string]$Permission
    )
    <#
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/recon/entities/rules/v1:post'
            Format = @{
                Body = @{
                    resources = @('name','id','description','settings')
                    root = @('resources')
                }
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
    #>
    process {
        if ($PSBoundParameters.Array) {
            if (!$Script:Falcon.Hostname) { Request-FalconToken }
            $Param = @{
                Path = "$($Script:Falcon.Hostname)/recon/entities/rules/v1"
                Method = 'post'
                Headers = @{
                    Accept = 'application/json'
                    ContentType = 'application/json'
                }
            }
            for ($i = 0; $i -lt ($PSBoundParameters.Array | Measure-Object).Count; $i += 500) {
                # Create rules in batches of 500
                $Group = $PSBoundParameters.Array[$i..($i + 499)]
                $Param['Body'] = ConvertTo-Json -InputObject @($Group) -Depth 8
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request
            }
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Format = @{ Body = @{ root = @('permissions','priority','name','filter','topic') }}
            }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Remove-FalconReconAction {
<#
.SYNOPSIS
Remove an action from a Falcon X Recon monitoring rule
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Id
Action identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/actions/v1:delete')]
    param(
        [Parameter(ParameterSetName='/recon/entities/actions/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Remove-FalconReconNotification {
<#
.SYNOPSIS
Remove Falcon X Recon notifications
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Id
Notification identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/notifications/v1:delete')]
    param(
        [Parameter(ParameterSetName='/recon/entities/notifications/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{76}$')]
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
function Remove-FalconReconRule {
<#
.SYNOPSIS
Remove Falcon X Recon monitoring rules
.DESCRIPTION
Requires 'Monitoring Rules (Falcon X Recon): Write'.
.PARAMETER Id
Monitoring rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-X-Recon
#>
    [CmdletBinding(DefaultParameterSetName='/recon/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName='/recon/entities/rules/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
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