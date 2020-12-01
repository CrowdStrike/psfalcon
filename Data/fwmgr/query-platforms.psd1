@{
  Name = "fwmgr/query-platforms"
  Path = "/fwmgr/queries/platforms/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get the list of platform names"
  Parameters = @(
    @{ 
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Description = "Maximum number of results per request"
      Position = 1
    }
    @{ 
      Dynamic = "Offset"
      Name = "offset"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Position to begin retrieving results"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.msa.QueryResponse"
  }
}