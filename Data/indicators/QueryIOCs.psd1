@{
  Name = "indicators/QueryIOCs"
  Path = "/indicators/queries/iocs/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "iocs:read"
  Description = "Search the custom IOCs in your customer account"
  Parameters = @(
    @{
      Dynamic = "Type"
      Name = "types"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "sha256"
        "md5"
        "domain"
        "ipv4"
        "ipv6"
      )
      Description = "Type of indicator"
      Position = 1
    }
    @{
      Dynamic = "Value"
      Name = "values"
      Type = "string"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 200
      Description = "The string representation of the indicator"
      Position = 2
    }
    @{
      Dynamic = "FromExpirationTimestamp"
      Name = "from.expiration_timestamp"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Find custom IOCs created after this time (RFC-3339 timestamp)"
      Position = $null
    }
    @{
      Dynamic = "ToExpirationTimestamp"
      Name = "to.expiration_timestamp"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Find custom IOCs created before this time (RFC-3339 timestamp)"
      Position = $null
    }
    @{
      Dynamic = "Policy"
      Name = "policies"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "detect"
        "none"
      )
      Description = "Custom IOC policy type"
      Position = $null
    }
    @{
      Dynamic = "Sources"
      Name = "sources"
      Type = "string"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 200
      Description = "The source where this indicator originated. This can be used for tracking where this indicator was defined."
      Position = $null
    }
    @{
      Dynamic = "ShareLevels"
      Name = "share_levels"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "red"
      )
      Description = "The level at which the indicator will be shared. Currently only red share level (not shared) is supported indicating that the IOC isn't shared with other FH customers."
      Position = $null
    }
    @{
      Dynamic = "CreatedBy"
      Name = "created_by"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The user or API client who created the Custom IOC"
      Position = $null
    }
    @{
      Dynamic = "DeletedBy"
      Name = "deleted_by"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The user or API client who deleted the Custom IOC"
      Position = $null
    }
    @{
      Dynamic = "IncludeDeleted"
      Name = "include_deleted"
      Type = "bool"
      In = @( "query" )
      Required = $false
      Description = "Include deleted IOCs"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOCIDs"
  }
}