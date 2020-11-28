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
      Dynamic = "Processes"
      Type = "switch"
      Required = $true
      Description = "Retrieve process identifiers for a host that has observed a custom IOC"
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
      Dynamic = "HostId"
      Name = "device_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Target Host identifier"
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
    200 = "api.MsaReplyProcessesRanOn"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}