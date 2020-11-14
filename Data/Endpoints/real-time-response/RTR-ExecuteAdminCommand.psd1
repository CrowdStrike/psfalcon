@{
  Name = "real-time-response/RTR-ExecuteAdminCommand"
  Path = "/real-time-response/entities/admin-command/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Issue a Real-time Response command to an existing session"
  Parameters = @(
    @{
      Dynamic = "Command"
      Name = "base_command"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "put"
        "run"
        "runscript"
      )
      Description = "Command to issue"
      Position = 1
    }
  )
  Responses = @{
    201 = "domain.CommandExecuteResponseWrapper"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}