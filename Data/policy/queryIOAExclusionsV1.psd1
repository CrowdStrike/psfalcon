@{
  Name = "policy/queryIOAExclusionsV1"
  Description = "Search for IOA exclusions."
  Path = "/policy/queries/ioa-exclusions/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "self-service-ioa-exclusions:read"
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Description = "Maximum number of results per request"
      Type = "int"
      In = @( "query" )
      Min = 1
      Max = 500
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}