@{
  Name = "policy/getMLExclusionsV1"
  Description = "Get a set of ML Exclusions by specifying their IDs"
  Path = "/policy/entities/ml-exclusions/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "ml-exclusions:read"
  Parameters = @{
    Dynamic = "ExclusionIds"
    Name = "ids"
    Required = $true
    Description = "One or more exclusion identifiers"
    Type = "array"
    In = @( "query" )
    Pattern = "\w{32}"
    Position = 1
  }
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.MlExclusionRespV1"
  }
}