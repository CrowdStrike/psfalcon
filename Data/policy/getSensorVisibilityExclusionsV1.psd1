@{
  Name = "policy/getSensorVisibilityExclusionsV1"
  Description = "Get a set of Sensor Visibility Exclusions by specifying their IDs"
  Path = "/policy/entities/sv-exclusions/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-visibility-exclusions:read"
  Parameters = @{
    Dynamic = "ExclusionIds"
    Name = "ids"
    Required = $true
    Description = "One or more exclusion identifiers"
    Type = "array"
    In = @(
      "query"
    )
    Pattern = "\w{32}"
    Position = 1
  }
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.SvExclusionRespV1"
  }
}