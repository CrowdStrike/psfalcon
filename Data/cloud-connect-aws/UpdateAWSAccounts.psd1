@{
  Name = "cloud-connect-aws/UpdateAWSAccounts"
  Path = "/cloud-connect-aws/entities/accounts/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:write"
  Description = "Update AWS Accounts by specifying the ID of the account and details to update"
  Parameters = @(
    @{
      Dynamic = "CloudtrailId"
      Name = "cloudtrail_bucket_owner_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set it takes precedence of the settings level field."
    }
    @{
      Dynamic = "CloudtrailRegion"
      Name = "cloudtrail_bucket_region"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "Region where the S3 bucket containing cloudtrail logs resides."
    }
    @{
      Dynamic = "ExternalId"
      Name = "external_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "ID assigned for use with cross account IAM role access."
    }
    @{
      Dynamic = "IamRoleArn"
      Name = "iam_role_arn"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The full arn of the IAM role created in this account to control access."
    }
    @{
      Dynamic = "AccountId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Pattern = "\d{12}"
      Description = "12 digit AWS provided unique identifier for the account."
    }
    @{
      Dynamic = "RateLimitReqs"
      Name = "rate_limit_reqs"
      Type = "int"
      In = @( "body" )
      Parent = "resources"
      Description = "Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time threshold."
    }
    @{
      Dynamic = "RateLimitTime"
      Name = "rate_limit_time"
      Type = "int"
      In = @( "body" )
      Parent = "resources"
      Description = "Rate limiting setting to control the number of seconds for which -RateLimitReqs applies."
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "models.AWSAccountsV1"
  }
}