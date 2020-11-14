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
      Dynamic = "RegEx"
      Name = "value"
      Required = $false
      Description = "RegEx pattern for the exclusion"
      Type = "string"
      In = @( "body" )
      Position = 2
    }
    @{
      Dynamic = "Exclude"
      Name = "excluded_from"
      Required = $false
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
      Dynamic = "GroupIds"
      Name = "groups"
      Required = $false
      Description = "One or more host group identifiers or 'all'"
      Type = "array"
      In = @( "body" )
      Pattern = "(\w{32}|all)"
      Position = 4
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "body" )
      Position = 5
    }
  )
  Responses = @{
    200 = "responses.MlExclusionRespV1"
    400 = "responses.MlExclusionRespV1"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.MlExclusionRespV1"
  }
}