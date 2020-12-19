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
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "models.CustomerConfigurationsV1"
  }
}