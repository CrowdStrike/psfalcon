@{
  Name = "real-time-response/RTR-ListFiles"
  Path = "/real-time-response/entities/file/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Get a list of files for the specified RTR session."
  Parameters = @(
    @{
      Dynamic = "SessionId"
      Name = "session_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Real-time Response session identifier"
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.ListFilesResponseWrapper"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
  }
}