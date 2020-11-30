@{
  Name = "fwmgr/get-firewall-fields"
  Path = "/fwmgr/entities/firewall-fields/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "List detailed information about Firewall Management fields"
  Parameters = @(
    @{
      Dynamic = "FieldIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The field identifiers to retrieve"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.api.FirewallFieldsResponse"
  }
}