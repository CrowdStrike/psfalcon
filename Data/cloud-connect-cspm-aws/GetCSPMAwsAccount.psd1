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
      Pattern = "\d{12}"
      Description = "AWS account IDs"
    }
    @{
      Dynamic = "OrganizationIds"
      Name = "organization-ids"
      Type = "array"
      In = @( "query" )
      Pattern = "^o-[0-9a-z]{10,32}$"
      Description = "AWS organization IDs"
    }
    @{
      Dynamic = "Status"
      Name = "status"
      Type = "string"
      In = @( "query" )
      Enum = @(
        "provisioned",
        "operational"
      )
      Description = "Account status to filter results by."
    }
    @{
      Dynamic = "ScanType"
      Name = "scan-type"
      Type = "string"
      In = @( "query" )
      Enum = @(
        "full",
        "dry"
      )
      Description = "Type of scan, dry or full, to perform on selected accounts"
    }
  )
  Responses = @{
    default = "registration.AWSAccountResponseV2"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
