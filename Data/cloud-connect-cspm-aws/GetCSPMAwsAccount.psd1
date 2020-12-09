@{
  Name = "cloud-connect-cspm-aws/GetCSPMAwsAccount"
  Method = "get"
  Path = "/cloud-connect-cspm-aws/entities/account/v1"
  Description = "Returns information about the current status of an AWS account."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "AccountIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $false
      Pattern = "\d{12}"
      Position = $null
      Description = "AWS account IDs"
    }
    @{
      Dynamic = "OrganizationIds"
      Name = "organization-ids"
      Type = "array"
      In = @( "query" )
      Required = $false
      Pattern = "^o-[0-9a-z]{10,32}$"
      Position = $null
      Description = "AWS organization IDs"
    }
    @{
      Dynamic = "Status"
      Name = "status"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "provisioned",
        "operational"
      )
      Position = $null
      Description = "Account status to filter results by."
    }
    @{
      Dynamic = "ScanType"
      Name = "scan-type"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "full",
        "dry"
      )
      Position = $null
      Description = "Type of scan, dry or full, to perform on selected accounts"
    }
  )
  Responses = @{
    default = "registration.AWSAccountResponseV2"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
