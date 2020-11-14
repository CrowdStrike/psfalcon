@{
  Name = "cloud-connect-aws/VerifyAWSAccountAccess"
  Path = "/cloud-connect-aws/entities/verify-account-access/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:write"
  Description = "Performs an Access Verification check on the specified AWS Account IDs"
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
    200 = "models.VerifyAccessResponseV1"
    400 = "models.VerifyAccessResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.VerifyAccessResponseV1"
  }
}