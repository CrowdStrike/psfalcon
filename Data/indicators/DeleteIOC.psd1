@{
  Name = "indicators/DeleteIOC"
  Path = "/indicators/entities/iocs/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:write"
  Description = "Delete a custom IOC"
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
    200 = "api.MsaReplyIOC"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}