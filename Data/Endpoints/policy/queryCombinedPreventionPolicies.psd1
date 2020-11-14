@{
  Name = "policy/queryCombinedPreventionPolicies"
  Path = "/policy/combined/prevention/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "prevention-policies:read"
  Description = "Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a set of Prevention Policies which match the filter criteria"
  Parameters = @()
  Responses = @{
    200 = "responses.PreventionPoliciesV1"
    400 = "responses.PreventionPoliciesV1"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.PreventionPoliciesV1"
  }
}