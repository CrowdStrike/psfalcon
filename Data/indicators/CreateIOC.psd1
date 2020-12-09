@{
  Name = "indicators/CreateIOC"
  Path = "/indicators/entities/iocs/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:write"
  Description = "Create custom IOCs"
  Parameters = @(
    @{
      Dynamic = "Type"
      Name = "type"
      Type = "string"
      In = @( "body" )
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
      In = @( "body" )
      Required = $true
      Description = "Indicator value"
      Position = 2
    }
    @{
      Dynamic = "Policy"
      Name = "policy"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "detect"
        "none"
      )
      Description = "Action to take when a host observes the indicator"
      Position = 3
    }
    @{
      Dynamic = "ExpirationDays"
      Name = "expiration_days"
      Type = "int"
      In = @( "body" )
      Required = $false
      Description = "Number of days before expiration (for 'domain' 'ipv4' and 'ipv6')"
      Position = 4
    }
    
    @{
      Dynamic = "ShareLevel"
      Name = "share_level"
      Type = "string"
      In = @( "body" )
      Required = 5
      Enum = @(
        "red"
      )
      Description = "Indicator visibility level"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Indicator description"
      Position = 6
    }
    @{
      Dynamic = "Source"
      Name = "source"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Indicator source"
      Position = 7
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOC"
  }
}