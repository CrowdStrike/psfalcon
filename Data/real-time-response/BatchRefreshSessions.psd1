@{
  Name = "real-time-response/BatchRefreshSessions"
  Path = "/real-time-response/combined/batch-refresh-session/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Refresh a batch Real-time Response session to avoid hitting the default timeout of 10 minutes"
  Parameters = @(
    @{
      Dynamic = "BatchId"
      Name = "batch_id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "Real-time Response batch session identifier"
      Position = 1
    }
    @{
      Dynamic = "RemoveHostIds"
      Name = "hosts_to_remove"
      Type = "array"
      In = @( "body" )
      Required = $false
      Pattern = "\w{32}"
      Description = "One or more Host identifiers to remove from the batch session"
      Position = 2
    }
    @{
      Dynamic = "Timeout"
      Name = "timeout"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 30
      Max = 600
      Description = "Length of time to wait for a result in seconds"
      Position = 3
    }
  )
  Responses = @{
    201 = "domain.BatchRefreshSessionResponse"
    400 = "domain.APIError"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
  }
}