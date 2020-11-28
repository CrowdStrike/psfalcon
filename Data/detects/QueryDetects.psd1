@{
  Name = "detects/QueryDetects"
  Path = "/detects/queries/detects/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "detects:read"
  Description = "Search for detection IDs that match a given query"
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 9999
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
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
    default = "msa.QueryResponse"
  }
}