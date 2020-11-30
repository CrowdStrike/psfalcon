@{
  Name = "devices/QueryDevicesByFilterScroll"
  Path = "/devices/queries/devices-scroll/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "devices:read"
  Description = "Search for hosts"
  Parameters = @(
    @{
      Dynamic = "Offset"
      Name = "offset"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "A pagination token used with the Limit parameter to manage pagination of results"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.DeviceResponse"
  }
}