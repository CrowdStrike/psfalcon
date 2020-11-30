@{
  Name = "policy/deletePreventionPolicies"
  Path = "/policy/entities/prevention/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "prevention-policies:write"
  Description = "Delete Prevention policies"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more policy identifiers"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}