@{
  Name = "policy/getPreventionPolicies"
  Path = "/policy/entities/prevention/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "prevention-policies:read"
  Description = "Retrieve a set of Prevention policies"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "Prevention policy identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.PreventionPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.PreventionPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.PreventionPoliciesV1"
  }
}