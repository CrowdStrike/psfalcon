@{
  Name = "cloud-connect-gcp/GetCSPMCGPAccount"
  Path = "/cloud-connect-gcp/entities/account/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:read"
  Description = "Returns information about the current status of an GCP account."
  Parameters = @(
    @{
      Dynamic = "ScanType"
      Name = "scan-type"
      Type = "string"
      In = @( "query" )
      Enum = @(
        "dry"
        "full"
      )
      Description = "Type of scan dry or full to perform on selected accounts"
    }
    @{
      Dynamic = "ParentIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Pattern = "\d{10}"
      Description = "Parent IDs of accounts"
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.GCPAccountResponseV1"
  }
}