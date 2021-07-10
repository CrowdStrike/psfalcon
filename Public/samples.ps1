function Get-FalconSample {
<#
.Synopsis
List accessible malware samples
.Parameter Ids
One or more SHA256 hash values
.Role
samplestore:read
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/queries/samples/GET/v1:post')]
    param(
        [Parameter(ParameterSetName = '/samples/queries/samples/GET/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids
    )
    begin {
        # Rename parameter for API submission
        $PSBoundParameters.Add('sha256s', $PSBoundParameters.Ids)
        [void] $PSBoundParameters.Remove('Ids')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Send-FalconSample {
<#
.Synopsis
Upload a file up to 100MB in size for further cloud analysis
.Parameter Path
Path to local file
.Parameter FileName
Name of the file
.Parameter IsConfidential
Defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console.

$true: File is only shown to users within your customer account (default)
$false: File can be seen by other CrowdStrike customers
.Parameter Comment
A descriptive comment to identify the file for other users
.Role
samplestore:write
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
        @('Filename', 'IsConfidential', 'Path').foreach{
            if ($PSBoundParameters.$_) {
                # Rename parameter for API submission
                $Field = switch ($_) {
                    'Filename'       { 'file_name' }
                    'IsConfidential' { 'is_confidential' }
                    'Path'           { 'body' }
                }
                $PSBoundParameters.Add($Field, $PSBoundParameters.$_)
                [void] $PSBoundParameters.Remove($_)
            }
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('comment', 'file_name', 'is_confidential')
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
function Receive-FalconSample {
<#
.Synopsis
Download a malware sample
.Parameter Id
SHA256 hash value
.Parameter Path
Destination path
.Parameter PasswordProtected
Archive and password protect the sample with password 'infected'
.Role
samplestore:read
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/entities/samples/v3:get')]
    param(
        [Parameter(ParameterSetName = '/samples/entities/samples/v3:get', Mandatory = $true, Position = 1)]
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
        # Rename parameter for API submission
        $PSBoundParameters.Add('ids', $PSBoundParameters.Id)
        [void] $PSBoundParameters.Remove('Id')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
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
Removes a sample, including file, meta and submissions from the collection
.Parameter Id
SHA256 hash value
.Role
samplestore:write
#>
    [CmdletBinding(DefaultParameterSetName = '/samples/entities/samples/v3:delete')]
    param(
        [Parameter(ParameterSetName = '/samples/entities/samples/v3:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id
    )
    begin {
        # Rename parameter for API submission
        $PSBoundParameters.Add('ids', $PSBoundParameters.Id)
        [void] $PSBoundParameters.Remove('Id')
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
