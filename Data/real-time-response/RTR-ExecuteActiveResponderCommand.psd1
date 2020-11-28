@{
  Name = "real-time-response/RTR-ExecuteActiveResponderCommand"
  Path = "/real-time-response/entities/active-responder-command/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Issue a Real-time Response command to an existing session"
  Parameters = @(
    @{
      Dynamic = "Command"
      Name = "base_command"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "cp"
        "encrypt"
        "get"
        "kill"
        "map"
        "memdump"
        "mkdir"
        "mv"
        "reg set"
        "reg delete"
        "reg load"
        "reg unload"
        "restart"
        "rm"
        "shutdown"
        "umount"
        "unmap"
        "update"
        "xmemdump"
        "zip"
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