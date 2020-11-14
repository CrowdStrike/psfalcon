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
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Custom IOC description"
      Position = $null
    }
    @{
      Dynamic = "ExpirationDays"
      Name = "expiration_days"
      Type = "int"
      In = @( "body" )
      Required = $false
      Description = "Number of days before expiration (for 'domain' 'ipv4' and 'ipv6')"
      Position = $null
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
      Description = "Action to take when a host observes the custom IOC"
      Position = $null
    }
    @{
      Dynamic = "ShareLevel"
      Name = "share_level"
      Type = "string"
      In = @( "body" )
      Required = $false
      Enum = @(
        "red"
      )
      Description = "Custom IOC visibility level"
      Position = $null
    }
    @{
      Dynamic = "Source"
      Name = "source"
      Type = "string"
      In = @( "body" )
      Required = $false
      Min = 1
      Max = 200
      Description = "Custom IOC source"
      Position = $null
    }
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
      Description = "Custom IOC type"
      Position = $null
    }
    @{
      Dynamic = "Value"
      Name = "value"
      Type = "string"
      In = @( "body" )
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