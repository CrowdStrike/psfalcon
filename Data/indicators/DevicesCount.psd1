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
      Dynamic = "TotalCount"
      Type = "switch"
      Required = $true
      Description = "Retrieve the total number of hosts that have observed a custom IOC"
      Position = $null
    }
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
      Description = "Custom IOC type"
      Position = $null
    }
    @{
      Dynamic = "Value"
      Name = "value"
      Type = "string"
      In = @( "query" )
      Required = $true
      Min = 1
      Max = 200
      Description = "Custom IOC value"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOCDevicesCount"
  }
}