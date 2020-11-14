
@{
  Name = "installation-tokens/tokens-query"
  Path = "/installation-tokens/queries/tokens/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:read"
  Description = "Search for tokens by providing an FQL filter and paging details."
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 1000
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}
