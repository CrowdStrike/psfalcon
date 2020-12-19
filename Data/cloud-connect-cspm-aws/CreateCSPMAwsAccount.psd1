@{
  Name = "cloud-connect-cspm-aws/CreateCSPMAwsAccount"
  Method = "post"
  Path = "/cloud-connect-cspm-aws/entities/account/v1"
  Description = "Creates a new account in our system for a customer and generates a script for them to run in their AWS cloud environment to grant us access."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "AccountId"
      Name = "account_id"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Position = 1
      Description = "AWS account identifier"
    }
    @{
      Dynamic = "OrganizationId"
      Name = "organization_id"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Position = 2
      Description = "AWS organization identifier"
    }
  )
  Responses = @{
    400 = "registration.AWSAccountResponseV2"
    207 = "registration.AWSAccountResponseV2"
    429 = "msa.ReplyMetaOnly"
    201 = "registration.AWSAccountResponseV2"
    500 = "registration.AWSAccountResponseV2"
    403 = "msa.ReplyMetaOnly"
  }
}
