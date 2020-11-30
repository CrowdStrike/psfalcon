@{
  Name = "policy/getFirewallPolicies"
  Path = "/policy/entities/firewall/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "List detailed information about Firewall Policies"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the Firewall Policies to return"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.FirewallPoliciesV1"
  }
}