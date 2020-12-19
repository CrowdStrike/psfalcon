
@{
  Name = "installation-tokens/customer-settings-read"
  Path = "/installation-tokens/entities/customer-settings/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:read"
  Description = "List installation token settings"
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "api.customerSettingsResponseV1"
  }
}
