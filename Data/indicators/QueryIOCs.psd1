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
      Description = "Indicator type"
      Position = 1
    }
    @{
      Dynamic = "Value"
      Name = "values"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Indicator value"
      Position = 2
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
      Description = "Indicator policy type"
      Position = 3
    }
    @{
      Dynamic = "Sources"
      Name = "sources"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Indicator source"
      Position = 4
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
      Description = "Visibility level"
      Position = 5
    }
    @{
      Dynamic = "FromExpirationTimestamp"
      Name = "from.expiration_timestamp"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Find indicators created after this time (RFC-3339 timestamp)"
      Position = 6
    }
    @{
      Dynamic = "ToExpirationTimestamp"
      Name = "to.expiration_timestamp"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Find indicators created before this time (RFC-3339 timestamp)"
      Position = 7
    }
    @{
      Dynamic = "CreatedBy"
      Name = "created_by"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The user or API client who created the indicator"
      Position = 8
    }
    @{
      Dynamic = "DeletedBy"
      Name = "deleted_by"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The user or API client who deleted the indicator"
      Position = 9
    }
    @{
      Dynamic = "IncludeDeleted"
      Name = "include_deleted"
      Type = "bool"
      In = @( "query" )
      Required = $false
      Description = "Include deleted indicators"
      Position = 10
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.MsaReplyIOCIDs"
  }
}