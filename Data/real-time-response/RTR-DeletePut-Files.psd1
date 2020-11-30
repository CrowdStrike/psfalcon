@{
  Name = "real-time-response/RTR-DeletePut-Files"
  Path = "/real-time-response/entities/put-files/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Delete a put-file based on the ID given.  Can only delete one file at a time."
  Parameters = @(
    @{
      Dynamic = "FileId"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "File identifier"
      Position = 1
    }
  )
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}