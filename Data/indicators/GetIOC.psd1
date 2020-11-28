@{
  Name = "indicators/GetIOC"
  Path = "/indicators/entities/iocs/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:read"
  Description = "Get detailed information about an IOC"
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
      Description = "Indicator type @('sha256' 'md5' 'domain' 'ipv4' 'ipv6')"
      Position = $null
    }
    @{
      Dynamic = "Value"
      Name = "value"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Indicator value"
      Position = $null
    }
  )
  Responses = @{
    200 = "api.MsaReplyIOC"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}