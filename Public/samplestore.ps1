function Get-FalconSample {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Remove-FalconSample {
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
            $PSBoundParameters['FileName'] = [System.IO.Path]::GetFileName($PSBoundParameters.Path)
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