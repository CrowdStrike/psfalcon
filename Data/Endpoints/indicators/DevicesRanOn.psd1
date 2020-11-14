@{
  Name = "indicators/DevicesRanOn"
  Path = "/indicators/queries/devices/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:read"
  Description = "List the host identifiers that have observed a custom IOC"
  Parameters = @(
    @{
      Dynamic = "Observed"
      Type = "switch"
      Required = $true
      Description = "Retrieve host identifiers for hosts that have observed a custom IOC"
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
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 100
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    200 = "api.MsaReplyDevicesRanOn"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}