@{
  Name = "cloud-connect-aws/ProvisionAWSAccounts"
  Path = "/cloud-connect-aws/entities/accounts/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:write"
  Description = "Provision AWS Accounts by specifying details about the accounts to provision"
  Parameters = @(
    @{
      Dynamic = "Mode"
      Name = "mode"
      Type = "string"
      In = @( "query" )
      Parent = "resources"
      Required = $false
      Enum = @(
        "cloudformation"
        "manual"
      )
      Description = "Provisioning mode"
      Position = $null
    }
    @{
      Dynamic = "CloudtrailId"
      Name = "cloudtrail_bucket_owner_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set it takes precedence of the settings level field."
      Position = $null
    }
    @{
      Dynamic = "CloudtrailRegion"
      Name = "cloudtrail_bucket_region"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Region where the S3 bucket containing cloudtrail logs resides."
      Position = $null
    }
    @{
      Dynamic = "ExternalId"
      Name = "external_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "ID assigned for use with cross account IAM role access."
      Position = $null
    }
    @{
      Dynamic = "IamRoleArn"
      Name = "iam_role_arn"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The full arn of the IAM role created in this account to control access."
      Position = $null
    }
    @{
      Dynamic = "AccountId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "12 digit AWS provided unique identifier for the account."
      Position = $null
    }
    @{
      Dynamic = "RateLimitReqs"
      Name = "rate_limit_reqs"
      Type = "int"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time threshold."
      Position = $null
    }
    @{
      Dynamic = "RateLimitTime"
      Name = "rate_limit_time"
      Type = "int"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Rate limiting setting to control the number of seconds for which -RateLimitReqs applies."
      Position = $null
    }
  )
  Responses = @{
    201 = "models.AWSAccountsV1"
    400 = "models.AWSAccountsV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.AWSAccountsV1"
  }
}