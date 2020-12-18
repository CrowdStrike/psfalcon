@{
  Name = "cloud-connect-cspm-azure/DeleteCSPMAzureAccount"
  Method = "delete"
  Path = "/cloud-connect-cspm-azure/entities/account/v1"
  Description = "Deletes an Azure subscription from the system."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "SubscriptionIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 1
      Description = "Azure subscription IDs to remove"
    }
  )
  Responses = @{
    default = "registration.BaseResponseV1"
    500 = "registration.AzureAccountResponseV1"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
