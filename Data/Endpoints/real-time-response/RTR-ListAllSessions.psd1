@{
  Name = "real-time-response/RTR-ListAllSessions"
  Path = "/real-time-response/queries/sessions/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Get a list of session_ids."
  Parameters = @()
  Responses = @{
    200 = "domain.ListSessionsResponseMsa"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
  }
}