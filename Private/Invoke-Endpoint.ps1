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
        [Parameter(Mandatory = $true)]
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
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            Add-Type -AssemblyName System.Net.Http
        }
        if ((-not($Falcon.Token)) -or (($Falcon.Expires) -le (Get-Date).AddSeconds(30)) -and
        ($Endpoint -ne 'oauth2/oauth2AccessToken')) {
            Request-FalconToken
        }
        $Target = $Falcon.Endpoint($Endpoint)

        $FullUri = if ($Path) {
            "$($Falcon.Hostname)$($Path)"
        }
        else {
            "$($Falcon.Hostname)$($Target.Path)"
        }
        if ($Query) {
            $FullUri += "?$($Query -join '&')"
        }
    }
    process {
        $Client = [System.Net.Http.HttpClient]::New()
        $Method = [System.Net.Http.HttpMethod]::($Target.Method)
        $Uri = [System.Uri]::New($FullUri)
        $Request = [System.Net.Http.HttpRequestMessage]::New($Method, $Uri)
        $Param = @{
            Endpoint = $Target
            Request = $Request
        }
        if ($Header) {
            $Param['Header'] = $Header
        }
        Format-Header @Param
        if ($Query -match 'timeout') {
            $Timeout = [int] ($Query | Where-Object { $_ -match 'timeout' }).Split('=')[1] + 5
            $Client.Timeout = (New-TimeSpan -Seconds $Timeout).Ticks
            Write-Verbose ("[$($MyInvocation.MyCommand.Name)] HttpClient timeout set to $($Timeout) seconds")
        }
        Write-Verbose ("[$($MyInvocation.MyCommand.Name)] $(($Target.Method).ToUpper())" +
            " $($Falcon.Hostname)$($Target.Path)")
        try {
            if ($Formdata) {
                $MultiContent = [System.Net.Http.MultipartFormDataContent]::New()
                foreach ($Key in $Formdata.Keys) {
                    if ($Key -match '(file|upfile)') {
                        $FileStream = [System.IO.FileStream]::New($Formdata.$Key, [System.IO.FileMode]::Open)
                        $Filename = [System.IO.Path]::GetFileName($Formdata.$Key)
                        $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
                        $MultiContent.Add($StreamContent, $Key, $Filename)
                    }
                    else {
                        $StringContent = [System.Net.Http.StringContent]::New($Formdata.$Key)
                        $MultiContent.Add($StringContent, $Key)
                    }
                }
                $Request.Content = $MultiContent
            }
            elseif ($Body) {
                $Request.Content = if ($Body -is [string]) {
                    [System.Net.Http.StringContent]::New($Body, [System.Text.Encoding]::UTF8,
                        ($Target.Headers.ContentType))
                }
                else {
                    $Body
                }
            }
            $Response = if ($Outfile) {
                ($Request.Headers.GetEnumerator()).foreach{
                    $Client.DefaultRequestHeaders.Add($_.Key, $_.Value)
                }
                $Request.Dispose()
                $Client.GetByteArrayAsync($Uri)
            }
            else {
                $Client.SendAsync($Request)
            }
            if ($Response.Result -is [System.Byte[]]) {
                [System.IO.File]::WriteAllBytes($Outfile, ($Response.Result))
                if (Test-Path $Outfile) {
                    Get-ChildItem $Outfile | Out-Host
                }
            }
            elseif ($Response.Result) {
                Format-Result -Response $Response -Endpoint $Endpoint
            }
            else {
                $ErrParam = @{
                    TargetObject = "$($Falcon.Hostname)$($Falcon.Endpoint($Endpoint).Path)"
                    Category = 'ConnectionError'
                    CategoryTargetName = "$($Falcon.Endpoint($Endpoint).Path)"
                    CategoryTargetType = "$($Falcon.Endpoint($Endpoint).Method)"
                    Message = "Unable to contact $($Falcon.Hostname)"
                    RecommendedAction = 'Check connectivity and proxy configuration'
                }
                Write-Error @ErrParam
            }
        }
        catch {
            $_
        }
    }
    end {
        if ($Response.Result.Headers) {
            Wait-RetryAfter $Response.Result.Headers
        }
        if ($Response) {
            $Response.Dispose()
        }
    }
}