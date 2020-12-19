@{
  Name = "policy/updateMLExclusionsV1"
  Description = "Update the ML exclusions"
  Path = "/policy/entities/ml-exclusions/v1"
  Method = "patch"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "ml-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "ExclusionId"
      Name = "id"
      Required = $true
      Description = "Exclusion identifier"
      Type = "string"
      In = @( "body" )
      Position = 1
    }
    @{
      Dynamic = "GroupIds"
      Name = "groups"
      Description = "One or more host group identifiers or 'all'"
      Type = "array"
      In = @( "body" )
      Pattern = "(\w{32}|all)"
      Position = 2
    }
    @{
      Dynamic = "ExcludedFrom"
      Name = "excluded_from"
      Description = "Operations to exclude"
      Type = "array"
      In = @( "body" )
      Enum = @(
        "blocking"
        "extraction"
      )
      Position = 3
    }
    @{
      Dynamic = "Pattern"
      Name = "value"
      Description = "RegEx pattern for the exclusion"
      Type = "string"
      In = @( "body" )
      Position = 4
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "body" )
      Position = 5
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.MlExclusionRespV1"
  }
}