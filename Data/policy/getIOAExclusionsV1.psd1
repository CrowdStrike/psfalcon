@{
  Name = "policy/getIOAExclusionsV1"
  Description = "Get a set of IOA Exclusions by specifying their IDs"
  Path = "/policy/entities/ioa-exclusions/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "self-service-ioa-exclusions:read"
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
    default = "responses.IoaExclusionRespV1"
  }
}