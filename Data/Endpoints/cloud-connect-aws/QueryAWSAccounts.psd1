@{
  Name = "cloud-connect-aws/QueryAWSAccounts"
  Path = "/cloud-connect-aws/combined/accounts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:read"
  Description = "Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS accounts which match the filter criteria"
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
    200 = "models.AWSAccountsV1"
    400 = "models.AWSAccountsV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.AWSAccountsV1"
  }
}