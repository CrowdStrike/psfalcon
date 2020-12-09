@{
  Name = "indicators/ProcessesRanOn"
  Path = "/indicators/queries/processes/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:read"
  Description = "Search for processes associated with a custom IOC"
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
    @{
      Dynamic = "HostId"
      Name = "device_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Host identifier"
      Position = 3
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
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyProcessesRanOn"
  }
}