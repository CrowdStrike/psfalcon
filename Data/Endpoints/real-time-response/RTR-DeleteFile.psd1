@{
  Name = "real-time-response/RTR-DeleteFile"
  Path = "/real-time-response/entities/file/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Delete a RTR session file."
  Parameters = @(
    @{
      Dynamic = "FileId"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "File identifier"
      Position = $null
    }
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
    204 = "msa.ReplyMetaOnly"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
  }
}