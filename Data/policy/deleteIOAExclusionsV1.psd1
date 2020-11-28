@{
  Name = "policy/deleteIOAExclusionsV1"
  Description = "Delete the IOA exclusions by id"
  Path = "/policy/entities/ioa-exclusions/v1"
  Method = "delete"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "self-service-ioa-exclusions:write"
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
      Required = $false
      Description = "Explains why this exclusions was deleted"
      Type = "string"
      In = @( "query" )
      Position = 2
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}