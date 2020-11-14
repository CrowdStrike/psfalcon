@{
  Name = "policy/queryMLExclusionsV1"
  Description = "Search for ML exclusions."
  Path = "/policy/queries/ml-exclusions/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "ml-exclusions:read"
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Required = $false
      Description = "Maximum number of results per request"
      Type = "int"
      In = @( "query" )
      Min = 1
      Max = 500
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}