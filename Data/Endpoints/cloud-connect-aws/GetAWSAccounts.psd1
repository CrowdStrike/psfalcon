@{
  Name = "cloud-connect-aws/GetAWSAccounts"
  Path = "/cloud-connect-aws/entities/accounts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:read"
  Description = "List AWS Accounts"
  Parameters = @(
    @{
      Dynamic = "AccountIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\d{12}"
      Description = "One or more AWS account identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "models.AWSAccountsV1"
    400 = "models.AWSAccountsV1"
    403 = "msa.ReplyMetaOnly"
    404 = "models.AWSAccountsV1"
    429 = "msa.ReplyMetaOnly"
    500 = "models.AWSAccountsV1"
  }
}