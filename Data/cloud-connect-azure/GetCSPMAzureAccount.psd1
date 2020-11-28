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
      Required = $false
      Pattern = "^(0-9a-z-){36}$"
      Description = "SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned."
      Position = $null
    }
    @{
      Dynamic = "ScanType"
      Name = "scan-type"
      Type = "string"
      In = @( "query" )
      Parent = "resources"
      Required = $false
      Enum = @(
        "dry"
        "full"
      )
      Description = "Type of scan dry or full to perform on selected accounts"
      Position = $null
    }
  )
  Responses = @{
    200 = "registration.AzureAccountResponseV1"
    207 = "registration.AzureAccountResponseV1"
    400 = "registration.AzureAccountResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.AzureAccountResponseV1"
  }
}