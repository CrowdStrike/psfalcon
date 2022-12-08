class ApiClient {
    [System.Net.Http.HttpClientHandler]$Handler
    [System.Net.Http.HttpClient]$Client
    [System.Collections.Hashtable]$Collector
    ApiClient() {
        $this.Handler = [System.Net.Http.HttpClientHandler]::New()
        $this.Client = [System.Net.Http.HttpClient]::New($this.Handler)
        $this.Collector = $null
    }
    [string] Path([string]$Path) {
        $Output = if (![IO.Path]::IsPathRooted($Path)) {
            $FullPath = Join-Path -Path (Get-Location).Path -ChildPath $Path
            $FullPath = Join-Path -Path $FullPath -ChildPath '.'
            [IO.Path]::GetFullPath($FullPath)
        } else {
            $Path
        }
        return $Output
    }
    [System.Object] Invoke([System.Object]$Param) {
        Write-Verbose "[ApiClient.Invoke] $($Param.Method.ToUpper()) $($Param.Path)"
        if ($Param.Headers) {
            [string]$Verbose = $Param.Headers.GetEnumerator().foreach{ "$($_.Key)=$($_.Value)" } -join ', '
            if ($Verbose) { Write-Verbose "[ApiClient.Invoke] $Verbose" }
        }
        try {
            $Output = if ($Param.Outfile) {
                @($Param.Headers.Keys).foreach{ $this.Client.DefaultRequestHeaders.Add($_,$Param.Headers.$_) }
                $Request = $this.Client.GetByteArrayAsync($Param.Path)
                if ($Request.Result) {
                    [System.IO.File]::WriteAllBytes($this.Path($Param.Outfile),$Request.Result)
                    Write-Verbose "[ApiClient.Invoke] Output directed to '$($Param.Outfile)'."
                }
                @($Param.Headers.Keys).foreach{
                    if ($this.Client.DefaultRequestHeaders.$_) { $this.Client.DefaultRequestHeaders.Remove($_) }
                }
            } else {
                $Message = [System.Net.Http.HttpRequestMessage]::New($Param.Method.ToUpper(),$Param.Path)
                ($Param.Headers).GetEnumerator().foreach{ $Message.Headers.Add($_.Key,$_.Value) }
                if ($Param.Formdata) {
                    $Message.Content = [System.Net.Http.MultipartFormDataContent]::New()
                    ($Param.Formdata).GetEnumerator().foreach{
                        $Verbose = if ($_.Key -match '^(file|upfile)$') {
                            $FileStream = [System.IO.FileStream]::New($this.Path($_.Value),
                                [System.IO.FileMode]::Open)
                            $Filename = [System.IO.Path]::GetFileName($this.Path($_.Value))
                            $FileType = [System.IO.Path]::GetExtension($this.Path($_.Value)) -replace '^.',$null
                            $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
                            if ($FileType -eq 'zip') {
                                $StreamContent.Headers.ContentType = 'application',$FileType -join '/'
                            } elseif ($FileType -eq '7z') {
                                $StreamContent.Headers.ContentType = 'application/x-7z-compressed'
                            }
                            $Message.Content.Add($StreamContent,$_.Key,$Filename)
                            @($_.Key,'<StreamContent>') -join '='
                        } else {
                            $Message.Content.Add([System.Net.Http.StringContent]::New($_.Value),$_.Key)
                            @($_.Key,$_.Value) -join '='
                        }
                        Write-Verbose "[ApiClient.Invoke] $($Verbose -join ', ')"
                    }
                } elseif ($Param.Body) {
                    $Message.Content = if ($Param.Body -is [string] -and $Param.Headers.ContentType) {
                        [System.Net.Http.StringContent]::New($Param.Body,[System.Text.Encoding]::UTF8,
                            $Param.Headers.ContentType)
                        if ($Param.Path -notmatch '/oauth2/token$') {
                            Write-Verbose "[ApiClient.Invoke] $($Param.Body)"
                        }
                    } else {
                        $Param.Body
                    }
                }
                if ($this.Collector.Enable -contains 'requests') { $this.Log($Message) }
                $this.Client.SendAsync($Message)
            }
            if ($Output.Result.StatusCode) {
                Write-Verbose "[ApiClient.Invoke] $(@($Output.Result.StatusCode.GetHashCode(),
                    $Output.Result.StatusCode) -join ': ')"
            }
            if ($Output.Result.Headers) {
                Write-Verbose "[ApiClient.Invoke] $($Output.Result.Headers.GetEnumerator().foreach{
                    @($_.Key,(@($_.Value) -join ', ')) -join '=' } -join ', ')"
            }
            if ($Output.Result -and $this.Collector.Enable -contains 'responses') { $this.Log($Output.Result) }
        } catch {
            throw $_
        }
        return $Output
    }
    [void] Log([System.Object]$Object) {
        $Item = @{
            timestamp = Get-Date -Format o
            attributes = @{ Headers = @{} }
        }
        if ($Object -is [System.Net.Http.HttpRequestMessage]) {
            @('RequestUri','Method').foreach{ $Item.Attributes[$_] = $Object.$_.ToString() }
            $Object.Headers.GetEnumerator().Where({ $_.Key -ne 'Authorization' }).foreach{
                $Item.Attributes.Headers[$_.Key] = $_.Value
            }
            if ($Object.Content -is [System.Net.Http.StringContent]) {
                $Item.Attributes['StringContent'] = ($Object.Content.ReadAsStringAsync().Result -replace
                    'client_secret=\w+&?','client_secret=redacted')
            }
        } elseif ($Object -is [System.Net.Http.HttpResponseMessage]) {
            $Object.Headers.GetEnumerator().foreach{ $Item.Attributes.Headers[$_.Key] = $_.Value }
            if ($Object.Content -and ($Object.Content.Headers.ContentType -eq 'application/json' -or
            $Object.Content.Headers.ContentType.MediaType -eq 'application/json')) {
                @(($Object.Content.ReadAsStringAsync().Result | ConvertFrom-Json).PSObject.Properties).Where({
                $_.Name -ne 'access_token' }).foreach{
                    $Item.Attributes[$_.Name] = $_.Value
                }
            } elseif ($Object.Content) {
                $Item.Attributes['StringContent'] = $Object.Content.ReadAsStringAsync().Result
            }
        }
        $Job = @{
            Name = 'ApiClient_Log',$Item.timestamp -join '.'
            ScriptBlock = { $Param = $args[0]; Invoke-RestMethod @Param }
            ArgumentList = @{
                Uri = $this.Collector.Uri
                Method = 'post'
                Headers = @{
                    Authorization = 'Bearer',$this.Collector.Token -join ' '
                    ContentType = 'application/json'
                }
                Body = ConvertTo-Json @(
                    @{
                        tags = @{
                            host = [System.Net.Dns]::GetHostName()
                            source = $this.Client.DefaultRequestHeaders.UserAgent.ToString()
                        }
                        events = @(,$Item)
                    }
                ) -Depth 8 -Compress
            }
        }
        [void](Start-Job @Job)
        Write-Verbose "[ApiClient.Log] Submitted job '$($Job.Name)'."
        @(Get-Job | Where-Object { $_.Name -match '^ApiClient_Log' -and $_.State -eq 'Completed' }).foreach{
            Write-Verbose "[ApiClient.Log] Removed job '$($_.Name)'."
            Remove-Job -Id $_.Id
        }
    }
}