@{
  Name = "sensors/listAvailableStreamsOAuth2"
  Path = "/sensors/entities/datafeed/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "streaming:read"
  Description = "Discover all event streams in your environment"
  Parameters = @(
    @{
      Dynamic = "AppId"
      Name = "appId"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{1,32}"
      Description = "Label that identifies your connection. Max: 32 alphanumeric characters (a-z A-Z 0-9)."
      Position = $null
    }
    @{
      Dynamic = "Format"
      Name = "format"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "json"
        "flatjson"
      )
      Description = "Format for streaming events"
      Position = $null
    }
  )
  Responses = @{
    200 = "main.discoveryResponseV2"
    400 = "main.discoveryResponseV2"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "main.discoveryResponseV2"
  }
}