@{
  Name = "indicators/UpdateIOC"
  Path = "/indicators/entities/iocs/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:write"
  Description = "Update a custom IOC"
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
      Description = "Custom IOC type"
      Position = 1
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
      Position = 2
    }
    @{
      Dynamic = "Policy"
      Name = "policy"
      Type = "string"
      In = @( "body" )
      Required = $false
      Enum = @(
        "detect"
        "none"
      )
      Description = "Action to take when a host observes the custom IOC"
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
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Custom IOC description"
      Position = 5
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
      Position = 6
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
      Position = 7
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOC"
  }
}