@{
  Name = "cloud-connect-azure/GetCSPMAzureUserScripts"
  Path = "/cloud-connect-azure/entities/user-scripts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:read"
  Description = "Outputs a script to run in an Azure environment to grant access to the Falcon platform"
  Responses = @{
    200 = "registration.AzureProvisionGetUserScriptResponseV1"
    207 = "registration.AzureProvisionGetUserScriptResponseV1"
    400 = "registration.AzureProvisionGetUserScriptResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.AzureProvisionGetUserScriptResponseV1"
  }
}