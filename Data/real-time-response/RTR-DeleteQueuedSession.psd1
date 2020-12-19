@{
  Name = "real-time-response/RTR-DeleteQueuedSession"
  Path = "/real-time-response/entities/queued-sessions/command/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Delete a queued session command"
  Parameters = @(
    @{
      Dynamic = "SessionId"
      Name = "session_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Real-time Response session identifier"
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
    }
    @{
      Dynamic = "CloudRequestId"
      Name = "cloud_request_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "Cloud request identifier of the executed command"
    }
  )
  Responses = @{
    204 = "msa.ReplyMetaOnly"
    400 = "domain.APIError"
    401 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}