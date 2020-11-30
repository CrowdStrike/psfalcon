@{
  Name = "real-time-response/RTR-ListQueuedSessions"
  Path = "/real-time-response/entities/queued-sessions/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Get queued session metadata by session ID"
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
    @{
      Dynamic = "Queue"
      Type = "switch"
      Required = $true
      Description = "Lists information about sessions in the offline queue"
      Position = $null
    }
  )
  Responses = @{
    400 = "domain.APIError"
    401 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    default = "domain.QueuedSessionResponseWrapper"
  }
}