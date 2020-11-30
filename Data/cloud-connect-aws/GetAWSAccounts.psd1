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
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "models.AWSAccountsV1"
  }
}