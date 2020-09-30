function Send-Sample {
<#
.SYNOPSIS
    Upload a sample to submit to the sandbox
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'UploadSampleV2')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('UploadSampleV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if ($Dynamic.Path.Value -match '^\.') {
            # Convert relative path to absolute path
            $Dynamic.Path.Value = $Dynamic.Path.Value -replace '^\.', $pwd
        }
        if (-not $Dynamic.FileName.Value) {
            # Capture filename from path
            $Dynamic.FileName.Value = [System.IO.Path]::GetFileName($Dynamic.Path.Value)
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ((Test-Path $Dynamic.Path.Value) -eq $false) {
                # Output exception for invalid file path
                throw "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
            }
            # Evaluate input and make request
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}
