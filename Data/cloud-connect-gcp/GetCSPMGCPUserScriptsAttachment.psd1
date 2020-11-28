@{
  Name = "cloud-connect-gcp/GetCSPMGCPUserScriptsAttachment"
  Path = "/cloud-connect-gcp/entities/user-scripts-download/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "d4c-registration:read"
  Description = "Return a script for customer to run in their cloud environment to grant us access to their GCP environment as a downloadable attachment"
  Responses = @{
    200 = "registration.GCPProvisionGetUserScriptResponseV1"
    400 = "registration.GCPProvisionGetUserScriptResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.GCPProvisionGetUserScriptResponseV1"
  }
}