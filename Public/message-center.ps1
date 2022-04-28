function Add-FalconCompleteActivity {
<#
.SYNOPSIS
Add an activity to a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Type
Activity type
.PARAMETER Content
Activity content
.PARAMETER UserId
User identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-activity/v1:post')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
           Position=1)]
        [ValidateSet('comment',IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
           Position=2)]
        [Alias('body')]
        [string]$Content,
        [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [Alias('case_id')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('case_id','user_uuid','type','body') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Edit-FalconCompleteCase {
<#
.SYNOPSIS
Modify an existing Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Content
Case content
.PARAMETER DetectionId
Detection identifier
.PARAMETER IncidentId
Incident identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/entities/case/v1:patch')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',Position=1)]
        [Alias('body')]
        [string]$Content,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [Alias('detections','detection_id','DetectionIds')]
        [string[]]$DetectionId,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [Alias('incidents','incident_id','IncidentIds')]
        [string[]]$IncidentId,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('id','body','detections','incidents') }}
        }
        [System.Collections.Generic.List[string]]$LdtList = @()
        [System.Collections.Generic.List[string]]$IncList = @()
    }
    process {
        if ($DetectionId -or $IncidentId) {
            if ($DetectionId) { @($DetectionId).foreach{ $LdtList.Add($_) }}
            if ($IncidentId) { @($IncidentId).foreach{ $IncList.Add($_) }}
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($LdtList -or $IncList) {
            if ($LdtList) { $PSBoundParameters['DetectionId'] = $LdtList | Select-Object -Unique }
            if ($IncList) { $PSBoundParameters['IncidentId'] = $IncList | Select-Object -Unique }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconCompleteActivity {
<#
.SYNOPSIS
Search for Falcon Complete case activities
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Id
Activity identifier
.PARAMETER CaseId
Case identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/queries/case-activities/v1:get')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case-activities/GET/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Mandatory,Position=1)]
        [Alias('case_id')]
        [string]$CaseId,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=3)]
        [ValidateSet('activity.created_time.asc','activity.created_time.desc','activity.type.asc',
            'activity.type.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
        [string]$Offset,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('case_id','filter','sort','limit','offset')
            }
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
function Get-FalconCompleteCase {
<#
.SYNOPSIS
Search for Falcon Complete cases
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Id
Case identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/queries/cases/v1:get')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/cases/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=2)]
        [ValidateSet('case.created_time.asc','case.created_time.desc','case.id.asc','case.id.desc',
            'case.last_modified_time.asc','case.last_modified_time.desc','case.status.asc','case.status.desc',
            'case.type.asc','case.type.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
        [string]$Offset,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('filter','sort','limit','offset')
            }
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
function New-FalconCompleteCase {
<#
.SYNOPSIS
Create a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Type
Case type
.PARAMETER Title
Case title
.PARAMETER Content
Case content
.PARAMETER DetectionId
Detection identifier
.PARAMETER IncidentId
Incident identifier
.PARAMETER UserId
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/entities/case/v1:post')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',Mandatory,Position=1)]
        [ValidateSet('fc:detection-support','fc:contact','fc:falcon-product-support','fc:incident-support',
            IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',Mandatory,Position=2)]
        [string]$Title,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',Mandatory,Position=3)]
        [Alias('body')]
        [string]$Content,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [ValidateScript({
            if ($PSBoundParameters.Type -eq 'fc:detection-support') {
                $true
            } else {
                throw "Detection identifiers are used with type 'fc:detection-support'."
            }
        })]
        [Alias('detections','detection_id','DetectionIds')]
        [string[]]$DetectionId,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',ValueFromPipelineByPropertyName,
            Position=5)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [ValidateScript({
            if ($PSBoundParameters.Type -eq 'fc:incident-support') {
                $true
            } else {
                throw "Incident identifiers are used with type 'fc:incident-support'."
            }
        })]
        [Alias('incidents','incident_id','IncidentIds')]
        [string[]]$IncidentId,
        [Parameter(ParameterSetName='/message-center/entities/case/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=6)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid')]
        [string]$UserId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('body','detections','incidents','title','type','user_uuid') }
            }
        }
        [System.Collections.Generic.List[string]]$LdtList = @()
        [System.Collections.Generic.List[string]]$IncList = @()
    }
    process {
        if ($DetectionId -or $IncidentId) {
            if ($DetectionId) { @($DetectionId).foreach{ $LdtList.Add($_) }}
            if ($IncidentId) { @($IncidentId).foreach{ $IncList.Add($_) }}
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($LdtList -or $IncList) {
            if ($LdtList) { $PSBoundParameters['DetectionId'] = $LdtList | Select-Object -Unique }
            if ($IncList) { $PSBoundParameters['IncidentId'] = $IncList | Select-Object -Unique }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Receive-FalconCompleteAttachment {
<#
.SYNOPSIS
Download a Falcon Complete case attachment
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Attachment identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-attachment/v1:get')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get',Mandatory,Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [string]$Id,
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get')]
        [switch]$Force

    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('id')
                Outfile = 'path'
            }
        }
    }
    process {
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
function Send-FalconCompleteAttachment {
<#
.SYNOPSIS
Upload and attach a file to a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Path
Path to local file
.PARAMETER UserId
User identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Message-Center
#>
    [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-attachment/v1:post')]
    param(
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,Position=1)]
        [ValidatePattern('\.(bmp|csv|doc|docx|gif|jpg|jpeg|pdf|png|pptx|txt|xls|xlsx)$')]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
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
        [Alias('file')]
        [string]$Path,
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('case_id')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ ContentType = 'multipart/form-data' }
            Format = @{ Formdata = @('case_id','user_uuid','file') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}