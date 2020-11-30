@{
  Name = "policy/queryCombinedFirewallPolicies"
  Path = "/policy/combined/firewall/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Search for Firewall Policies in your environment by providing an FQL filter and paging details. Returns a set of Firewall Policies which match the filter criteria"
  Parameters = @()
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.FirewallPoliciesV1"
  }
}