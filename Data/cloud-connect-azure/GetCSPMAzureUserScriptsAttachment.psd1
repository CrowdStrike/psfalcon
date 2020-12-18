@{
  Name = "cloud-connect-azure/GetCSPMAzureUserScriptsAttachment"
  Path = "/cloud-connect-azure/entities/user-scripts-download/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "d4c-registration:read"
  Description = "Download a script to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment"
  Parameters = @(
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @( "outfile" )
      Required = $true
      Pattern = "^*\.sh$"
      Description = "Destination Path"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.AzureProvisionGetUserScriptResponseV1"
  }
}