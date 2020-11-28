@{
  Name = "ioarules/query-rule-types"
  Description = "Get all rule type IDs."
  Path = "/ioarules/queries/rule-types/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @(
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
    429 = "msa.ReplyMetaOnly"
  }
}