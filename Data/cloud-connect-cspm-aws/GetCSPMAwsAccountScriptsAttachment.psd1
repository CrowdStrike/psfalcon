@{
  Name = "cloud-connect-cspm-aws/GetCSPMAwsAccountScriptsAttachment"
  Method = "get"
  Path = "/cloud-connect-cspm-aws/entities/user-scripts-download/v1"
  Description = "Return a script for customer to run in their cloud environment to grant us access to their AWS environment as a downloadable attachment."
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "cspm-registration:read"
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
    default = "registration.AWSProvisionGetAccountScriptResponseV2"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}