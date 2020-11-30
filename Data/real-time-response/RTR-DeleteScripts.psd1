@{
  Name = "real-time-response/RTR-DeleteScripts"
  Path = "/real-time-response/entities/scripts/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Delete a custom-script based on the ID given.  Can only delete one script at a time."
  Parameters = @(
    @{
      Dynamic = "FileId"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Script identifier"
      Position = 1
    }
  )
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}