@{
  Name = "real-time-response/BatchAdminCmd"
  Path = "/real-time-response/combined/batch-admin-command/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Issue a Real-time Response command to an existing batch session"
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
    201 = "domain.MultiCommandExecuteResponseWrapper"
    400 = "domain.APIError"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
  }
}