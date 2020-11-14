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
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.FirewallPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.FirewallPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.FirewallPoliciesV1"
  }
}