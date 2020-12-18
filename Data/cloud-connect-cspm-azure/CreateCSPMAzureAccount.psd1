@{
  Name = "cloud-connect-cspm-azure/CreateCSPMAzureAccount"
  Method = "post"
  Path = "/cloud-connect-cspm-azure/entities/account/v1"
  Description = "Creates a new account in our system for a customer and generates a script for them to run in their cloud environment to grant us access."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "SubscriptionId"
      Name = "subscription_id"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 1
      Description = "Azure Subscription ID."
    }
    @{
      Dynamic = "TenantId"
      Name = "tenant_id"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 2
      Description = "Azure Tenant ID to use."
    }
    
  )
  Responses = @{
    400 = "registration.AzureAccountResponseV1"
    207 = "registration.AzureAccountResponseV1"
    429 = "msa.ReplyMetaOnly"
    201 = "registration.AzureAccountResponseV1"
    500 = "registration.AzureAccountResponseV1"
    403 = "msa.ReplyMetaOnly"
  }
}
