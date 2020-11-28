@{
  Name = "cloud-connect-aws/GetAWSSettings"
  Path = "/cloud-connect-aws/combined/settings/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cloud-connect-aws:read"
  Description = "Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts"
  Responses = @{
    200 = "models.CustomerConfigurationsV1"
    400 = "models.CustomerConfigurationsV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "models.CustomerConfigurationsV1"
    default = "models.CustomerConfigurationsV1"
  }
}