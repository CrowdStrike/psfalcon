@{
  Name = "real-time-response/RTR-ListSessions"
  Path = "/real-time-response/entities/sessions/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Get session metadata by session id."
  Parameters = @(
    @{
      Dynamic = "SessionIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "One or more session identifiers"
      Position = 1
    }
  )
  Responses = @{
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    default = "domain.SessionResponseWrapper"
  }
}