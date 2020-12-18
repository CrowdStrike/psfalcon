@{
  Name = "cloud-connect-cspm-azure/GetCSPMAzureUserScriptsAttachment"
  Method = "get"
  Path = "/cloud-connect-cspm-azure/entities/user-scripts-download/v1"
  Description = "Return a script for customer to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment"
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "TenantId"
      Name = "tenant-id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 1
      Description = "Tenant ID to generate script for. Defaults to most recently registered tenant."
    },
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @( "outfile" )
      Required = $true
      Pattern = "^*\.sh$"
      Description = "Destination Path"
      Position = 2
    }
  )
  Responses = @{
    default = "registration.AzureProvisionGetUserScriptResponseV1"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
