@{
  Name = "cloud-connect-cspm-azure/GetCSPMAzureAccount"
  Method = "get"
  Path = "/cloud-connect-cspm-azure/entities/account/v1"
  Description = "Return information about Azure account registration"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "SubscriptionIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = $null
      Description = "SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned."
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
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 500
      Position = $null
      Description = "Maximum number of results per request"
    }
  )
  Responses = @{
    default = "registration.AzureAccountResponseV1"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
