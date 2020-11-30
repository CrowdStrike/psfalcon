@{
  Name = "cloud-connect-azure/GetCSPMAzureUserScriptsAttachment"
  Path = "/cloud-connect-azure/entities/user-scripts-download/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "d4c-registration:read"
  Description = "Download a script to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment"
  Parameters = @()
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.AzureProvisionGetUserScriptResponseV1"
  }
}