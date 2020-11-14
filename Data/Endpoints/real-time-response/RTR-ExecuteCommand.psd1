@{
  Name = "real-time-response/RTR-ExecuteCommand"
  Path = "/real-time-response/entities/command/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Issue a Real-time Response command to an existing session"
  Parameters = @(
    @{
      Dynamic = "Command"
      Name = "base_command"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "cat"
        "cd"
        "clear"
        "csrutil"
        "env"
        "eventlog"
        "filehash"
        "getsid"
        "help"
        "history"
        "ifconfig"
        "ipconfig"
        "ls"
        "mount"
        "netstat"
        "ps"
        "reg query"
        "users"
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