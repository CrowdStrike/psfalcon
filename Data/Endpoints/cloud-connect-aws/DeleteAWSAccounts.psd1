@{
  Name = "cloud-connect-aws/DeleteAWSAccounts"
  Path = "/cloud-connect-aws/entities/accounts/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:write"
  Description = "Delete a set of AWS Accounts by specifying their IDs"
  Parameters = @(
    @{
      Dynamic = "AccountIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more AWS account identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "models.BaseResponseV1"
    400 = "models.BaseResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.BaseResponseV1"
  }
}