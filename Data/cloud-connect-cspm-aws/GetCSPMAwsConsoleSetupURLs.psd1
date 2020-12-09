@{
  Name = "cloud-connect-cspm-aws/GetCSPMAwsConsoleSetupURLs"
  Method = "get"
  Path = "/cloud-connect-cspm-aws/entities/console-setup-urls/v1"
  Description = "Return a URL for customer to visit in their cloud environment to grant us access to their AWS environment."
  Headers = @{
    Accept = "application/json"
  }
  Permission = "cspm-registration:read"
  Responses = @{
    default = "registration.AWSAccountConsoleURL"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}