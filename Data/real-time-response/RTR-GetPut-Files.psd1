@{
  Name = "real-time-response/RTR-GetPut-Files"
  Path = "/real-time-response/entities/put-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get put-files based on the ID's given. These are used for the RTR `put` command."
  Parameters = @(
    @{
      Dynamic = "FileIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more file identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "binservclient.MsaPFResponse"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
  }
}