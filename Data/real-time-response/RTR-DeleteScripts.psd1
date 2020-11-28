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
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}