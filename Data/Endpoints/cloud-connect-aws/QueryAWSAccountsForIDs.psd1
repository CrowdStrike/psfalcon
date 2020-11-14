@{
  Name = "cloud-connect-aws/QueryAWSAccountsForIDs"
  Path = "/cloud-connect-aws/queries/accounts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:read"
  Description = "Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS account IDs which match the filter criteria"
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
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}