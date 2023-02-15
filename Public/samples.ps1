function Get-FalconSample {
<#
.SYNOPSIS
Retrieve detailed information about accessible sample files
.DESCRIPTION
Requires 'Sample Uploads: Read'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSample
#>
    [CmdletBinding(DefaultParameterSetName='/samples/queries/samples/GET/v1:post',SupportsShouldProcess)]
    [OutputType([string],ParameterSetName='/samples/queries/samples/GET/v1:post')]
    param(
        [Parameter(ParameterSetName='/samples/queries/samples/GET/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [Alias('sha256s','sha256','Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('sha256s') }}
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Receive-FalconSample {
<#
.SYNOPSIS
Download a sample
.DESCRIPTION
Requires 'Sample Uploads: Read'.
.PARAMETER Path
Destination path
.PARAMETER PasswordProtected
Archive and password protect the sample with password 'infected'
.PARAMETER Id
Sha256 hash value
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconSample
#>
    [CmdletBinding(DefaultParameterSetName='/samples/entities/samples/v3:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/samples/entities/samples/v3:get',Mandatory,Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:get',Position=2)]
        [Alias('password_protected')]
        [boolean]$PasswordProtected,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=3)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [Alias('Ids')]
        [string]$Id,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{
                Query = @('ids','password_protected')
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
function Remove-FalconSample {
<#
.SYNOPSIS
Remove a sample
.DESCRIPTION
Requires 'Sample Uploads: Write'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSample
#>
    [CmdletBinding(DefaultParameterSetName='/samples/entities/samples/v3:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/samples/entities/samples/v3:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [Alias('Ids')]
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
function Send-FalconSample {
<#
.SYNOPSIS
Upload a sample file
.DESCRIPTION
A successful upload will provide a 'sha256' value that can be used in submissions to the Falcon Sandbox or
Falcon QuickScan.

Maximum file size is 256MB. ZIP and 7z archives will automatically redirect to 'Send-FalconSampleArchive'.

Requires 'Sample Uploads: Write'.
.PARAMETER IsConfidential
Prohibit sample from being displayed in MalQuery [default: True]
.PARAMETER Comment
Audit log comment
.PARAMETER Name
File name
.PARAMETER Path
Path to local file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconSample
#>
    [CmdletBinding(DefaultParameterSetName='/samples/entities/samples/v3:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Sample',ParameterSetName='/samples/entities/samples/v3:post')]
    param(
        [Parameter(ParameterSetName='/samples/entities/samples/v3:post',Position=1)]
        [Alias('is_confidential')]
        [boolean]$IsConfidential,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:post',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [Alias('file_name','FileName')]
        [string]$Name,
        [Parameter(ParameterSetName='/samples/entities/samples/v3:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [Alias('body','FullName')]
        [string]$Path
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ ContentType = 'application/octet-stream' }
            Format = @{
                Query = @('comment','file_name','is_confidential')
                Body = @{ root = @('body') }
            }
            Schema = 'Sample'
        }
    }
    process {
        if (!$PSBoundParameters.Name) {
            $PSBoundParameters['Name'] = [System.IO.Path]::GetFileName($PSBoundParameters.Path)
        }
        if ($PSBoundParameters.Path -match '\.(7z|zip)$') {
            Send-FalconSampleArchive @PSBoundParameters
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}