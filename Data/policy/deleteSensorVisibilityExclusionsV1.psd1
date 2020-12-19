@{
  Name = "policy/deleteSensorVisibilityExclusionsV1"
  Description = "Delete the sensor visibility exclusions by id"
  Path = "/policy/entities/sv-exclusions/v1"
  Method = "delete"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-visibility-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "ExclusionIds"
      Name = "ids"
      Required = $true
      Description = "One or more exclusion identifiers"
      Type = "array"
      In = @( "query" )
      Position = 1
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Description = "Explains why this exclusion was deleted"
      Type = "string"
      In = @( "query" )
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}