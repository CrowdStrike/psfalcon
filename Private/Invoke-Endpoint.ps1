function Invoke-Endpoint {
<#
.SYNOPSIS
    Makes a request to an API endpoint
.PARAMETER ENDPOINT
    Falcon endpoint
.PARAMETER HEADER
    Header key/value pair inputs
.PARAMETER QUERY
    An array of string values to append to the URI
.PARAMETER BODY
    Body string
.PARAMETER FORMDATA
    Formdata dictionary
.PARAMETER OUTFILE
    Path for file output
.PARAMETER PATH
    A modified 'path' value to use in place of the endpoint-defined string
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [string] $Endpoint,

        [Parameter()]
        [hashtable] $Header,

        [Parameter()]
        [array] $Query,

        [Parameter()]
        [object] $Body,

        [Parameter()]
        [System.Collections.IDictionary] $Formdata,

        [Parameter()]
        [string] $Outfile,

        [Parameter()]
        [string] $Path
    )
    begin {
        # Set Falcon endpoint target
        $Target = $Falcon.Endpoint($Endpoint)

        # Define 'path' for request
        $FullPath = if ($Path) {
            "$($Falcon.Hostname)$($Path)"
        } else {
            "$($Falcon.Hostname)$($Target.Path)"
        }
        if ($Query) {
            # Add query items to UriPath
            $FullPath += "?$($Query -join '&')"
        }
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # Add System.Net.Http
            Add-Type -AssemblyName System.Net.Http
        }
    }
    process {
        # Create Http request objects
        $Client = [System.Net.Http.HttpClient]::New()
        $Request = [System.Net.Http.HttpRequestMessage]::New(
            ([System.Net.Http.HttpMethod]::($Target.Method)), $FullPath)

        # Add headers
        $Param = @{
            Endpoint = $Target
            Request = $Request
        }
        if ($Header) {
            $Param['Header'] = $Header
        }
        Format-Header @Param

        Write-Verbose ("[$($MyInvocation.MyCommand.Name)] $(($Target.Method).ToUpper())" +
        " $($Falcon.Hostname)$($Target.Path)")

        try {
            if ($Formdata) {
                # Add multipart content
                $MultiContent = [System.Net.Http.MultipartFormDataContent]::New()

                foreach ($Key in $Formdata.Keys) {
                    if ((Test-Path $Formdata.$Key) -eq $true) {
                        # If file, read as bytes
                        $FileStream = [System.IO.File]::OpenRead($Formdata.$Key)
                        $Filename = [System.IO.Path]::GetFileName($Formdata.$Key)
                        $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
                        $MultiContent.Add($StreamContent, $Key, $Filename)
                    } else {
                        # Add as string
                        $StringContent = [System.Net.Http.StringContent]::New($Formdata.$Key)
                        $MultiContent.Add($StringContent, $Key)
                    }
                }
                $Request.Content = $MultiContent
            } elseif ($Body) {
                $Request.Content = if ($Body -is [string]) {
                    # Add string content
                    [System.Net.Http.StringContent]::New($Body, [System.Text.Encoding]::UTF8,
                        ($Target.Headers.ContentType))
                } else {
                    # Add ByteArray content
                    $Body
                }
            }
            # Make request
            $Response = if ($Outfile) {
                ($Request.Headers.GetEnumerator()).foreach{
                    # Add headers to HttpClient from HttpRequestMessage
                    $Client.DefaultRequestHeaders.Add($_.Key, $_.Value)
                }
                # Dispose of HttpRequestMessage
                $Request.Dispose()

                # Make direct request using HttpClient
                $Client.GetByteArrayAsync($FullPath)
            } else {
                # Send request
                $Client.SendAsync($Request)
            }
            if ($Response.Result -is [System.Byte[]]) {
                # Output response to file
                [System.IO.File]::WriteAllBytes($Outfile, ($Response.Result))
    
                if (Test-Path $Outfile) {
                    # Display successful output
                    Get-ChildItem $Outfile | Out-Host
                }
            } else {
                # Format output
                Format-Result $Response
            }
        } catch {
            # Output error
            throw $_
        }
    }
    end {
        if ($Response.Result.Headers) {
            # Check for rate limiting
            Wait-RetryAfter $Response.Result.Headers
        }
        if ($Response) {
            # Dispose open HttpClient
            $Response.Dispose()
        }
    }
}