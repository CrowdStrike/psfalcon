@{
  Name = "policy/deleteMLExclusionsV1"
  Description = "Delete the ML exclusions by id"
  Path = "/policy/entities/ml-exclusions/v1"
  Method = "delete"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "ml-exclusions:write"
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
      Description = "Explains why this exclusion was deleted"
      Type = "string"
      In = @( "query" )
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.MlExclusionRespV1"
  }
}