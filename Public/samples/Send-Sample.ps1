function Send-Sample {
    <#
    .SYNOPSIS
        Upload a sample for submission
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'samples/UploadSampleV2')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('samples/UploadSampleV2')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $Dynamic.FileName.Value) {
            $Dynamic.FileName.Value = "$([System.IO.Path]::GetFileName($Dynamic.Path.Value))"
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif (-not(Test-Path $Dynamic.Path.Value)) {
            throw "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}