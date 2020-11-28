@{
  Name = "real-time-response/RTR-GetScripts"
  Path = "/real-time-response/entities/scripts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command."
  Parameters = @(
    @{
      Dynamic = "ScriptIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more script identifiers"
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