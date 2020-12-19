@{
  Name = "cloud-connect-azure/UpdateCSPMAzureAccountClientID"
  Path = "/cloud-connect-azure/entities/client-id/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:write"
  Description = "Update an Azure service account"
  Parameters = @(
    @{
      Dynamic = "ClientId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "^(0-9a-z-){36}$"
      Description = "Client identifier to use for the Service Principal associated with the Azure account"
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.AzureServicePrincipalResponseV1"
  }
}