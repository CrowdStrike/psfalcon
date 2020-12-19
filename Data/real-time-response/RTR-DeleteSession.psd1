@{
  Name = "real-time-response/RTR-DeleteSession"
  Path = "/real-time-response/entities/sessions/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Delete a session."
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
  )
  Responses = @{
    204 = "msa.ReplyMetaOnly"
    400 = "domain.APIError"
    401 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}