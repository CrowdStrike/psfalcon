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
      # Convert partial file path to a full file path
      $FullPath = Join-Path -Path (Get-Location).Path -ChildPath $Path
      $FullPath = Join-Path -Path $FullPath -ChildPath '.'
      [IO.Path]::GetFullPath($FullPath)
    } else {
      $Path
    }
    return $Output
  }
  [System.Object] Invoke([System.Object]$Param) {
    # Send API endpoint and headers to verbose stream
    $this.Verbose('ApiClient.Invoke',($Param.Method.ToUpper(),$Param.Path -join ' '))
    if ($Param.Headers) {
      [string]$Verbose = $Param.Headers.GetEnumerator().foreach{ "$($_.Key)=$($_.Value)" } -join ', '
      if ($Verbose) { $this.Verbose('ApiClient.Invoke',$Verbose) }
    }
    $Output = try {
      # Create basic HTTP request message and add headers
      $Message = [System.Net.Http.HttpRequestMessage]::New($Param.Method.ToUpper(),$Param.Path)
      $Param.Headers.GetEnumerator().foreach{ $Message.Headers.Add($_.Key,$_.Value) }
      if ($Param.Formdata) {
        # Create Formdata message
        $Message.Content = [System.Net.Http.MultipartFormDataContent]::New()
        $Param.Formdata.GetEnumerator().foreach{
          $Verbose = if ($_.Key -match '^(file|upfile)$') {
            # With 'file' or 'upfile', create StreamContent from key/value pair
            $FileStream = [System.IO.FileStream]::New($this.Path($_.Value),
              [System.IO.FileMode]::Open)
            $Filename = [System.IO.Path]::GetFileName($this.Path($_.Value))
            $StreamContent = [System.Net.Http.StreamContent]::New($FileStream)
            $FileType = $this.StreamType($Filename)
            if ($FileType) { $StreamContent.Headers.ContentType = $FileType }
            $Message.Content.Add($StreamContent,$_.Key,$Filename)
            @($_.Key,'<StreamContent>') -join '='
          } else {
            # Add StringContent for other Formdata key/value pairs
            $Message.Content.Add([System.Net.Http.StringContent]::New($_.Value),$_.Key)
            @($_.Key,$_.Value) -join '='
          }
          $this.Verbose('ApiClient.Invoke',($Verbose -join ', '))
        }
      } elseif ($Param.Body) {
        $Message.Content = if ($Param.Body -is [string] -and $Param.Headers.ContentType) {
          # Add 'Body' as StringContent
          [System.Net.Http.StringContent]::New($Param.Body,[System.Text.Encoding]::UTF8,$Param.Headers.ContentType)
          if ($Param.Path -notmatch '/oauth2/token$') { $this.Verbose('ApiClient.Invoke',$Param.Body) }
        } else {
          $Param.Body
        }
      }
      # Log request when enabled
      if ($this.Collector.Enable -contains 'requests') { $this.Log($Message) }
      $Request = if ($Param.Outfile) {
        # Download file
        @($Param.Headers.Keys).foreach{ $this.Client.DefaultRequestHeaders.Add($_,$Param.Headers.$_) }
        $this.Verbose('ApiClient.Invoke','Receiving ByteArray content...')
        $this.Client.GetByteArrayAsync($Param.Path)
      } else {
        # Send request
        $this.Client.SendAsync($Message,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
      }
      if ($Param.Outfile -and $Request.Result) {
        try {
          # When file download is complete, direct to 'Outfile'
          $this.Verbose('ApiClient.Invoke',"Creating '$($Param.Outfile)'.")
          [System.IO.File]::WriteAllBytes($this.Path($Param.Outfile),$Request.Result)
        } catch {
          throw $_
        } finally {
          @($Param.Headers.Keys).foreach{
            if ($this.Client.DefaultRequestHeaders.$_) { $this.Client.DefaultRequestHeaders.Remove($_) }
          }
        }
      } elseif ($Request.Result.StatusCode) {
        # Output HTTP response code to verbose stream
        $HashCode = $Request.Result.StatusCode.GetHashCode()
        $this.Verbose('ApiClient.Invoke',($HashCode,$Request.Result.StatusCode -join ': '))
        if ($Request.Result.Headers) {
          # Output response headers to verbose stream and warn when 'X-Api-Deprecation' appears
          $this.Verbose('ApiClient.Invoke',"$($Request.Result.Headers.GetEnumerator().foreach{
            @($_.Key,(@($_.Value) -join ', ')) -join '=' } -join ', ')")
          @($Request.Result.Headers.GetEnumerator().Where({ $_.Key -match '^X-Api-Deprecation' })).foreach{
            Write-Warning ([string]$_.Key,[string]$_.Value -join ': ')
          }
        }
        if ($Request.Result.Content -and $this.Collector.Enable -contains 'responses') {
          # Log response when enabled
          $this.Log($Request.Result)
        }
        $RetryAfter = if ($HashCode -eq 429 -and $Param.Path -notmatch '/oauth2/token$') {
          # Capture 'X-Ratelimit-Retryafter' when present
          $Request.Result.Headers.GetEnumerator().Where({ $_.Key -eq 'X-Ratelimit-Retryafter' }).Value
        }
        if ($RetryAfter) {
          # Subtract current time from 'X-Ratelimit-Retryafter', warn, and retry when rate limited
          [int32]$Wait = (([System.DateTimeOffset]::FromUnixTimeSeconds($RetryAfter)).LocalDateTime -
            (Get-Date)).Seconds
          $Limit = $Request.Result.Headers.GetEnumerator().Where({ $_.Key -eq 'X-Ratelimit-Limit' }).Value
          $Remaining = $Request.Result.Headers.GetEnumerator().Where({ $_.Key -eq 'X-Ratelimit-Remaining' }).Value
          Write-Warning ('Rate limited for {0} second(s). [{1}, {2}]' -f $Wait,('Limit',$Limit -join '='),
            ('Remaining',$Remaining -join '='))
          Start-Sleep -Seconds $Wait
          $this.Invoke($Param)
        } elseif ($Request.Result.Content -and $Param.Path -notmatch '/oauth2/token$') {
          # Convert from Json or output string content
          if ($Request.Result.Content.Headers.ContentType -eq 'application/json' -or
          $Request.Result.Content.Headers.ContentType.MediaType -eq 'application/json') {
            ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result
          } else {
            ($Request.Result.Content).ReadAsStringAsync().Result
          }
        } else {
          # Output entire response
          $Request
        }
      }
    } catch {
      throw $_
    } finally {
      if ($Request) { $Request.Dispose() }
    }
    return $Output
  }
  [void] Log([System.Object]$Object) {
    # Create LogScale message payload from 'HttpRequestMessage' or 'HttpResponseMessage'
    $Item = @{ timestamp = Get-Date -Format o; attributes = @{ Headers = @{} }}
    if ($Object -is [System.Net.Http.HttpRequestMessage]) {
      @('RequestUri','Method').foreach{ $Item.attributes[$_] = $Object.$_.ToString() }
      $Object.Headers.GetEnumerator().Where({ $_.Key -ne 'Authorization' }).foreach{
        $Item.attributes.Headers[$_.Key] = $_.Value
      }
      if ($Object.Content) {
        # Redact 'client_secret' from request
        $Item.attributes['Content'] = $Object.Content.ReadAsStringAsync().Result -replace 'client_secret=\w+&?',
          'client_secret=redacted'
      }
    } elseif ($Object -is [System.Net.Http.HttpResponseMessage]) {
      $Object.Headers.GetEnumerator().foreach{ $Item.attributes.Headers[$_.Key] = $_.Value }
      if ($Object.Content -and ($Object.Content.Headers.ContentType -eq 'application/json' -or
      $Object.Content.Headers.ContentType.MediaType -eq 'application/json')) {
        @(($Object.Content.ReadAsStringAsync().Result | ConvertFrom-Json).PSObject.Properties).Where({
        $_.Name -ne 'access_token' }).foreach{
          # Add content, but exclude 'access_token'
          $Item.attributes[$_.Name] = $_.Value
        }
      } elseif ($Object.Content) {
        # Add content as a string when unable to determine if 'HttpRequestMessage' or 'HttpResponseMessage'
        $Item.attributes['Content'] = $Object.Content.ReadAsStringAsync().Result
      }
    }
    # Use Invoke-RestMethod to send to LogScale within a background job
    $Job = @{
      Name = 'ApiClient_Log',$Item.timestamp -join '.'
      ScriptBlock = { $Param = $args[0]; Invoke-RestMethod @Param }
      ArgumentList = @{
        Uri = $this.Collector.Uri
        Method = 'post'
        Headers = @{ Authorization = 'Bearer',$this.Collector.Token -join ' '; ContentType = 'application/json' }
        Body = ConvertTo-Json @(
          @{
            tags = @{
              host = [System.Net.Dns]::GetHostName()
              source = $this.Client.DefaultRequestHeaders.UserAgent.ToString()
            }
            events = @(,$Item)
          }
        ) -Depth 32 -Compress
      }
    }
    [void](Start-Job @Job)
    $this.Verbose('ApiClient.Log',"Submitted job '$($Job.Name)'.")
    @(Get-Job | Where-Object { $_.Name -match '^ApiClient_Log' -and $_.State -eq 'Completed' }).foreach{
      # Remove completed background jobs
      $this.Verbose('ApiClient.Log',"Removed job '$($_.Name)'.")
      Remove-Job -Id $_.Id
    }
  }
  [string] StreamType([string]$String) {
    [string]$Extension = [System.IO.Path]::GetExtension($String) -replace '^\.',$null
    $Output = switch -Regex ($Extension) {
      # Output string based on file extension
      '^(bmp|gif|jp(e?)g|png)$' { "image/$_" }
      '^(pdf|zip)$' { "application/$_" }
      '^7z$' { 'application/x-7z-compressed' }
      '^(csv|txt)$' { if ($_ -eq 'txt') { 'text/plain' } else { "text/$_" }}
      '^doc(x?)$' {
        if ($_ -match 'x$') {
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        } else {
          'application/msword'
        }
      }
      '^ppt(x?)$' {
        if ($_ -match 'x$') {
          'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        } else {
          'application/vnd.ms-powerpoint'
        }
      }
      '^xls(x?)$' {
        if ($_ -match 'x$') {
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        } else {
          'application/vnd.ms-excel'
        }
      }
    }
    return $Output
  }
  [void] Verbose([string]$Function,[string]$String) {
    Write-Verbose ((Get-Date -Format 'HH:mm:ss'),"[$Function]",$String -join ' ')
  }
}