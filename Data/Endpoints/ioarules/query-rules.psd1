@{
  Name = "ioarules/query-rules"
  Description = "Finds all rule IDs matching the query with optional filter."
  Path = "/ioarules/queries/rules/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @(
    @{
      Dynamic = "Query"
      Name = "q"
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Type = "string"
      In = @( "query" )
      Position = $null
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 500
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}