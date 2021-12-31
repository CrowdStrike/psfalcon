function Add-FalconCompleteActivity {
    [CmdletBinding(DefaultParameterSetName = '/message-center/entities/case-activity/v1:post')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case-activity/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Id,

        [Parameter(ParameterSetName = '/message-center/entities/case-activity/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/message-center/entities/case-activity/v1:post', Mandatory = $true,
            Position = 3)]
        [ValidateSet('comment')]
        [string] $Type,

        [Parameter(ParameterSetName = '/message-center/entities/case-activity/v1:post', Mandatory = $true,
            Position = 4)]
        [string] $Content
    )
    begin {
        $Fields = @{
            Content = 'body'
            Id      = 'case_id'
            UserId  = 'user_uuid'
        }
    }
    process {
        if (!$Script:Falcon.Hostname) {
            Request-FalconToken
        }
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/message-center/entities/case-activity/v1"
            Method  = 'post'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body    = @{}
        }
        (Update-FieldName -Fields $Fields -Inputs $PSBoundParameters).GetEnumerator().foreach{
            $Param.Body[$_.Key.ToLower()] = $_.Value
        }
        $Param.Body = ConvertTo-Json -InputObject $Param.Body
        if ($Script:Humio.Path -and $Script:Humio.Token) {
            $Script:Falcon.Request['Body'] = $Param.Body
        }
        $RequestTime = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result -Request $Request -Time $RequestTime
    }
}
function Edit-FalconCompleteCase {
    [CmdletBinding(DefaultParameterSetName = '/message-center/entities/case/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case/v1:patch', Mandatory = $true, Position = 1)]
        [string] $Id,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:patch', Position = 2)]
        [string] $Content,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:patch', Position = 3)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [array] $DetectionIds,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:patch', Position = 4)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [array] $IncidentIds
    )
    begin {
        $Fields = @{
            Content      = 'body'
            DetectionIds = 'detections'
            IncidentIds  = 'incidents'
        }
    }
    process {
        if (!$Script:Falcon.Hostname) {
            Request-FalconToken
        }
        @('DetectionIds','IncidentIds').foreach{
            if ($PSBoundParameters.$_) {
                [array] $PSBoundParameters.$_ = ($PSBoundParameters.$_).foreach{
                    @{ id = $_ }
                }
            }
        }
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/message-center/entities/case/v1"
            Method  = 'patch'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body    = @{}
        }
        (Update-FieldName -Fields $Fields -Inputs $PSBoundParameters).GetEnumerator().foreach{
            $Param.Body[$_.Key.ToLower()] = $_.Value
        }
        $Param.Body = ConvertTo-Json -InputObject $Param.Body
        if ($Script:Humio.Path -and $Script:Humio.Token) {
            $Script:Falcon.Request['Body'] = $Param.Body
        }
        $RequestTime = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result -Request $Request -Time $RequestTime
    }
}
function Get-FalconCompleteActivity {
    [CmdletBinding(DefaultParameterSetName = '/message-center/queries/case-activities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case-activities/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get', Mandatory = $true,
            Position = 1)]
        [string] $CaseId,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get', Position = 2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get', Position = 3)]
        [ValidateSet('activity.created_time.asc','activity.created_time.desc','activity.type.asc',
            'activity.type.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/message-center/queries/case-activities/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            CaseId = 'case_id'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format    = @{
                Body  = @{
                    root = @('ids')
                }
                Query = @('case_id', 'filter', 'sort', 'limit', 'offset')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteCase {
    [CmdletBinding(DefaultParameterSetName = '/message-center/queries/cases/v1:get')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/cases/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get', Position = 2)]
        [ValidateSet('case.created_time.asc','case.created_time.desc','case.id.asc','case.id.desc',
            'case.last_modified_time.asc','case.last_modified_time.desc','case.status.asc','case.status.desc',
            'case.type.asc','case.type.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/message-center/queries/cases/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format    = @{
                Body = @{
                    root = @('ids')
                }
                Query = @('filter', 'sort', 'limit', 'offset')
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconCompleteCase {
    [CmdletBinding(DefaultParameterSetName = '/message-center/entities/case/v1:post')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Mandatory = $true, Position = 2)]
        [ValidateSet('fc:detection-support','fc:contact','fc:falcon-product-support','fc:incident-support')]
        [string] $Type,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Mandatory = $true, Position = 3)]
        [string] $Title,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Mandatory = $true, Position = 4)]
        [string] $Content,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Position = 5)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [ValidateScript({
            if ($PSBoundParameters.Type -eq 'fc:detection-support') {
                $true
            } else {
                throw "Detection identifiers are used with type 'fc:detection-support'."
            }
        })]
        [array] $DetectionIds,

        [Parameter(ParameterSetName = '/message-center/entities/case/v1:post', Position = 6)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [ValidateScript({
            if ($PSBoundParameters.Type -eq 'fc:incident-support') {
                $true
            } else {
                throw "Incident identifiers are used with type 'fc:incident-support'."
            }
        })]
        [array] $IncidentIds
    )
    begin {
        $Fields = @{
            Content      = 'body'
            UserId       = 'user_uuid'
            DetectionIds = 'detections'
            IncidentIds  = 'incidents'
        }
    }
    process {
        if (!$Script:Falcon.Hostname) {
            Request-FalconToken
        }
        @('DetectionIds','IncidentIds').foreach{
            if ($PSBoundParameters.$_) {
                [array] $PSBoundParameters.$_ = ($PSBoundParameters.$_).foreach{
                    @{ id = $_ }
                }
            }
        }
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/message-center/entities/case/v1"
            Method  = 'post'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body    = @{}
        }
        (Update-FieldName -Fields $Fields -Inputs $PSBoundParameters).GetEnumerator().foreach{
            $Param.Body[$_.Key.ToLower()] = $_.Value
        }
        $Param.Body = ConvertTo-Json -InputObject $Param.Body
        if ($Script:Humio.Path -and $Script:Humio.Token) {
            $Script:Falcon.Request['Body'] = $Param.Body
        }
        $RequestTime = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result -Request $Request -Time $RequestTime
    }
}
function Receive-FalconCompleteAttachment {
    [CmdletBinding(DefaultParameterSetName = '/message-center/entities/case-attachment/v1:get')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case-attachment/v1:get', Mandatory = $true,
            Position = 1)]
        [array] $Id,

        [Parameter(ParameterSetName = '/message-center/entities/case-attachment/v1:get', Mandatory = $true,
            Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format    = @{
                Query   = @('id')
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
function Send-FalconCompleteAttachment {
    [CmdletBinding(DefaultParameterSetName = '/message-center/entities/case-attachment/v1:post')]
    param(
        [Parameter(ParameterSetName = '/message-center/entities/case-attachment/v1:post', Mandatory = $true,
            Position = 1)]
        [array] $Id,

        [Parameter(ParameterSetName = '/message-center/entities/case-attachment/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('\.(bmp|csv|doc|docx|gif|jpg|jpeg|pdf|png|pptx|txt|xls|xlsx)$')]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $Leaf = Split-Path $_ -Leaf
                if ($Leaf -match '\W') {
                    throw 'Filename contains invalid characters.'
                } elseif (((Split-Path $_ -Leaf) -Split '.')[0].Length -gt 255) {
                    throw 'Maximum filename length is 255 characters.'
                } else {
                    $true
                }
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [string] $Path
    )
    begin {
        $Fields = @{
            Id     = 'case_id'
            Path   = 'file'
            UserId = 'user_uuid'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'multipart/form-data'
            }
            Format    = @{
                Formdata = @('case_id', 'user_uuid', 'file')
            }
        }
        Invoke-Falcon @Param
    }
}