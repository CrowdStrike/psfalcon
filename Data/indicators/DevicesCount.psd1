@{
  Name = "indicators/DevicesCount"
  Path = "/indicators/aggregates/devices-count/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:read"
  Description = "List the number of hosts that have observed a custom IOC"
  Parameters = @(
    @{
      Dynamic = "Type"
      Name = "type"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "sha256"
        "md5"
        "domain"
        "ipv4"
        "ipv6"
      )
      Description = "Indicator type"
      Position = 1
    }
    @{
      Dynamic = "Value"
      Name = "value"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Indicator value"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOCDevicesCount"
  }
}