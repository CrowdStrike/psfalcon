class ApiClient {
    [System.Net.Http.HttpClientHandler] $Handler
    [System.Net.Http.HttpClient] $Client
    ApiClient() {
        $this.Handler = [System.Net.Http.HttpClientHandler]::New()
        $this.Client = [System.Net.Http.HttpClient]::New($this.Handler)
    }
    [string] Path([string] $Path) {
        $Output = if (![IO.Path]::IsPathRooted($Path)) {
            $FullPath = Join-Path -Path (Get-Location).Path -ChildPath $Path
            $FullPath = Join-Path -Path $FullPath -ChildPath '.'
            [IO.Path]::GetFullPath($FullPath)
        } else {
            $Path
        }
        return $Output
    }
    [object] Invoke([object] $Param) {
        Write-Verbose "[ApiClient.Invoke] $($Param.Method.ToUpper()) $($Param.Path)"
        if ($Param.Headers) {
            Write-Verbose "[ApiClient.Invoke] $(($Param.Headers.GetEnumerator().foreach{
                "$($_.Key): $($_.Value)"
            }) -join ', ')"
        }
        $Output = try {
            if ($Param.Outfile) {
                ($Param.Headers).GetEnumerator().foreach{
                    $this.Client.DefaultRequestHeaders.Add($_.Key, $_.Value)
                }
                $Request = $this.Client.GetByteArrayAsync($Param.Path)
                if ($Request.Result) {
                    [System.IO.File]::WriteAllBytes($this.Path($Param.Outfile), $Request.Result)
                }
                ($this.Client.DefaultRequestHeaders).GetEnumerator().foreach{
                    if ($Param.Headers.Keys -contains $_.Key) {
                        $this.Client.DefaultRequestHeaders.Remove($_.Key)
                    }
                }
            } else {
                $Message = [System.Net.Http.HttpRequestMessage]::New($Param.Method.ToUpper(), $Param.Path)
                ($Param.Headers).GetEnumerator().foreach{
                    $Message.Headers.Add($_.Key, $_.Value)
                }
                if ($Param.Formdata) {
                    $Message.Content = [System.Net.Http.MultipartFormDataContent]::New()
                    ($Param.Formdata).GetEnumerator().foreach{
                        if ($_.Key -match '^(file|upfile)$') {
                            $FileStream = [System.IO.FileStream]::New($this.Path($_.Value),
                                [System.IO.FileMode]::Open)
                            $Filename = [System.IO.Path]::GetFileName($this.Path($_.Value))
                            $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
                            $Message.Content.Add($StreamContent, $_.Key, $Filename)
                        } else {
                            $Message.Content.Add([System.Net.Http.StringContent]::New($_.Value), $_.Key)
                        }
                    }
                } elseif ($Param.Body) {
                    $Message.Content = if ($Param.Body -is [string] -and $Param.Headers.ContentType) {
                        [System.Net.Http.StringContent]::New($Param.Body, [System.Text.Encoding]::UTF8,
                            $Param.Headers.ContentType)
                    } else {
                        $Param.Body
                    }
                }
                $this.Client.SendAsync($Message)
            }
        } catch {
            throw $_
        }
        if ($Output.Result.StatusCode) {
            $ResponseCode = "$(@($Output.Result.StatusCode.GetHashCode(), $Output.Result.StatusCode) -join ': ')"
            Write-Verbose "[ApiClient.Invoke] $ResponseCode"
            if (!$Output.Result.Content) {
                Write-Error $ResponseCode
            }
        }
        return $Output
    }
}