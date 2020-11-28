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
    200 = "responses.FirewallPoliciesV1"
    400 = "responses.FirewallPoliciesV1"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.FirewallPoliciesV1"
  }
}