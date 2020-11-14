@{
  Name = "real-time-response/BatchGetCmd"
  Path = "/real-time-response/combined/batch-get-command/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Send a 'get' request to a batch Real-time Response session"
  Parameters = @(
    @{
      Dynamic = "Timeout"
      Name = "timeout"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 30
      Max = 600
      Description = "Length of time to wait for a result in seconds"
      Position = $null
    }
    @{
      Dynamic = "BatchId"
      Name = "batch_id"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Required = $true
      Description = "Real-time Response batch session identifier"
      Position = $null
    }
    @{
      Dynamic = "Path"
      Name = "file_path"
      Type = "string"
      In = @( "body" )
      Required = $true
      Description = "Full path to the file to be retrieved from each host"
      Position = $null
    }
    @{
      Dynamic = "OptionalHosts"
      Name = "optional_hosts"
      Type = "array"
      In = @( "body" )
      Pattern = "\w{32}"
      Required = $false
      Description = "Restrict the request to specific host identifiers"
      Position = $null
    }
  )
  Responses = @{
    201 = "domain.BatchGetCommandResponse"
    400 = "domain.APIError"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
  }
}