@{
  Name = "cloud-connect-azure/CreateCSPMAzureAccount"
  Path = "/cloud-connect-azure/entities/account/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:write"
  Description = "Creates a new Azure account and generates a script to grant access to the Falcon platform"
  Parameters = @(
    @{
      Dynamic = "SubscriptionId"
      Name = "subscription_id"
      Type = "string"
      In = @( "body" )
      Required = $false
      Pattern = "^(0-9a-z-){36}$"
      Description = "Azure subscription identifier"
      Position = $null
    }
    @{
      Dynamic = "TenantId"
      Name = "tenant_id"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Azure tenant identifier"
      Position = $null
    }
  )
  Responses = @{
    201 = "registration.AzureAccountResponseV1"
    207 = "registration.AzureAccountResponseV1"
    400 = "registration.AzureAccountResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.AzureAccountResponseV1"
  }
}