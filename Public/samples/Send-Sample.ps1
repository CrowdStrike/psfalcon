function Send-Sample {
<#
.SYNOPSIS
    Upload a sample for submission
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'samples/UploadSampleV2')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('samples/UploadSampleV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $Dynamic.FileName.Value) {
            # Capture filename from path
            $Dynamic.FileName.Value = "$([System.IO.Path]::GetFileName($Dynamic.Path.Value))"
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } elseif (-not(Test-Path $Dynamic.Path.Value)) {
            # Output exception for invalid file path
            throw "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}