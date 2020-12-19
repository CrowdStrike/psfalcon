@{
  Name = "real-time-response/RTR-ListScripts"
  Path = "/real-time-response/queries/scripts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get a list of custom-script ID's that are available to the user for the runscript command."
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Min = 1
      Max = 100
      Description = "Maximum number of results per request"
    }
  )
  Responses = @{
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    default = "binservclient.MsaPutFileResponse"
  }
}