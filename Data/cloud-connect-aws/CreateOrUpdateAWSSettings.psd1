@{
  Name = "cloud-connect-aws/CreateOrUpdateAWSSettings"
  Path = "/cloud-connect-aws/entities/settings/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:write"
  Description = "Create or update Global Settings which are applicable to all provisioned AWS accounts"
  Parameters = @(
    @{
      Dynamic = "CloudtrailId"
      Name = "cloudtrail_bucket_owner_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Pattern = "\d{12}"
      Description = "The 12 digit AWS account which is hosting the centralized S3 bucket of containing cloudtrail logs from multiple accounts."
    }
    @{
      Dynamic = "ExternalId"
      Name = "static_external_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "By setting this value all subsequent accounts that are provisioned will default to using this value as their external ID."
    }
  )
  Responses = @{
    201 = "models.CustomerConfigurationsV1"
    400 = "models.CustomerConfigurationsV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.CustomerConfigurationsV1"
  }
}