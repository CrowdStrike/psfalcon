@{
  Name = "intel/QueryIntelIndicatorIds"
  Path = "/intel/queries/indicators/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-indicators:read"
  Description = "Get indicators IDs that match provided FQL filters."
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 50000
      Description = "Maximum number of results per request"
      Position = $null
    }
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
    @{
      Dynamic = "IncludeDeleted"
      Name = "include_deleted"
      Type = "bool"
      In = @( "query" )
      Required = $false
      Description = "Include both published and deleted indicators"
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "msa.QueryResponse"
  }
}