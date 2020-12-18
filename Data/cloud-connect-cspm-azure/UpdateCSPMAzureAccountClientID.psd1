@{
  Name = "cloud-connect-cspm-azure/UpdateCSPMAzureAccountClientID"
  Method = "patch"
  Path = "/cloud-connect-cspm-azure/entities/client-id/v1"
  Description = "Update an Azure service account in our system by with the user-created client_id created with the public key we've provided"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "ClientId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 1
      Description = "ClientID to use for the Service Principal associated with the customer's Azure account"
    }
    @{
      Dynamic = "TenantId"
      Name = "tenant-id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 2
      Description = "Tenant ID to update client ID for. Required if multiple tenants are registered."
    }
  )
  Responses = @{
    400 = "registration.AzureServicePrincipalResponseV1"
    201 = "registration.AzureServicePrincipalResponseV1"
    500 = "registration.AzureServicePrincipalResponseV1"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
