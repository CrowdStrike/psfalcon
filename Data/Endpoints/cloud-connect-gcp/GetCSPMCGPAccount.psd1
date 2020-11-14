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
      Required = $false
      Enum = @(
        "dry"
        "full"
      )
      Description = "Type of scan dry or full to perform on selected accounts"
      Position = $null
    }
    @{
      Dynamic = "ParentIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $false
      Pattern = "\d{10}"
      Description = "Parent IDs of accounts"
      Position = $null
    }
  )
  Responses = @{
    200 = "registration.GCPAccountResponseV1"
    207 = "registration.GCPAccountResponseV1"
    400 = "registration.GCPAccountResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.GCPAccountResponseV1"
  }
}