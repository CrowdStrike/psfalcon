function Get-FalconSample {
<#
.Synopsis
List detailed information about accessible sample files
.Description
Requires 'samplestore:read'.
.Parameter Ids
Sample Sha256 hash value(s)
.Role
samplestore:read
.Example
PS>Get-FalconSample -Ids <id>, <id>

List information about samples <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/queries/samples/GET/v1:post')]
    param(
        [Parameter(ParameterSetName = '/samples/queries/samples/GET/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Ids = 'sha256s'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('sha256s')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconSample {
<#
.Synopsis
Download a sample
.Description
Requires 'samplestore:read'.
.Parameter Id
Sample Sha256 hash value
.Parameter Path
Destination path
.Parameter PasswordProtected
Archive and password protect the sample with password 'infected'
.Role
samplestore:read
.Example
PS>Receive-FalconSample -Id <id> -Path sample.exe

Download sample <id> as 'sample.exe'.
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/entities/samples/v3:get')]
    param(
        [Parameter(ParameterSetName = '/samples/entities/samples/v3:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/samples/entities/samples/v3:get', Mandatory = $true, Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/samples/entities/samples/v3:get', Position = 3)]
        [boolean] $PasswordProtected
    )
    begin {
        $Fields = @{
            Id                = 'ids'
            PasswordProtected = 'password_protected'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query   = @('ids', 'password_protected')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconSample {
<#
.Synopsis
Delete samples
.Description
Requires 'samplestore:write'.
.Parameter Id
Sample Sha256 hash value
.Role
samplestore:write
.Example
PS>Remove-FalconSample -Ids <id>, <id>

Delete samples <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/entities/samples/v3:delete')]
    param(
        [Parameter(ParameterSetName = '/samples/entities/samples/v3:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Send-FalconSample {
<#
.Synopsis
Upload a sample file up to 256MB in size
.Description
Requires 'samplestore:write'.

A successful upload will provide a 'sha256' value that can be used in submissions to the Falcon X Sandbox or
Falcon QuickScan.
.Parameter Path
Path to local file
.Parameter FileName
Name of the file
.Parameter IsConfidential
Prohibit sample from being displayed in MalQuery [default: $true]
.Parameter Comment
Sample comment
.Role
samplestore:write
.Example
PS>Send-FalconSample -Path virus.exe -Comment 'bad file'

Upload 'virus.exe' with the comment 'bad file'.
.Example
PS>Send-FalconSample -Path samples.zip

Upload 'samples.zip' containing multiple samples in a single archive.
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/entities/samples/v3:post')]
    param(
        [Parameter(ParameterSetName = '/samples/entities/samples/v3:post', Mandatory = $true, Position = 1)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/samples/entities/samples/v3:post', Position = 2)]
        [string] $FileName,

        [Parameter(ParameterSetName = '/samples/entities/samples/v3:post', Position = 3)]
        [boolean] $IsConfidential,

        [Parameter(ParameterSetName = '/samples/entities/samples/v3:post', Position = 4)]
        [string] $Comment
    )
    begin {
        if (!$PSBoundParameters.FileName) {
            $PSBoundParameters.Add('FileName',([System.IO.Path]::GetFileName($PSBoundParameters.Path)))
        }
        $Fields = @{
            FileName       = if ($PSBoundParameters.Path -match '\.zip$') {
                'name'
            } else {
                'file_name'
            }
            IsConfidential = 'is_confidential'
            Path           = 'body'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = if ($PSBoundParameters.Path -match '\.zip$') {
                '/archives/entities/archives/v1:post'
            } else {
                $PSCmdlet.ParameterSetName
            }
            Headers  = @{
                ContentType = 'application/octet-stream'
            }
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('comment', 'file_name', 'name', 'is_confidential')
                Body  = @{
                    root = @('body')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}