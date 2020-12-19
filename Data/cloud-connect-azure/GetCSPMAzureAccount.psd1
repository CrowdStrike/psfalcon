@{
  Name = "cloud-connect-azure/GetCSPMAzureAccount"
  Path = "/cloud-connect-azure/entities/account/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:read"
  Description = "Return information about Azure account registration"
  Parameters = @(
    @{
      Dynamic = "SubscriptionIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Parent = "resources"
      Pattern = "^(0-9a-z-){36}$"
      Description = "SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned."
    }
    @{
      Dynamic = "ScanType"
      Name = "scan-type"
      Type = "string"
      In = @( "query" )
      Parent = "resources"
      Enum = @(
        "dry"
        "full"
      )
      Description = "Type of scan dry or full to perform on selected accounts"
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.AzureAccountResponseV1"
  }
}