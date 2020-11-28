@{
  Name = "sensors/GetSensorInstallersByQuery"
  Path = "/sensors/queries/installers/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-installers:read"
  Description = "Get sensor installer IDs by provided query"
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 500
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}