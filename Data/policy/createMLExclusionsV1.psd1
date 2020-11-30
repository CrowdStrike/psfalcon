@{
  Name = "policy/createMLExclusionsV1"
  Description = "Create the ML exclusions"
  Path = "/policy/entities/ml-exclusions/v1"
  Method = "post"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "ml-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "RegEx"
      Name = "value"
      Required = $true
      Description = "RegEx pattern for the exclusion"
      Type = "string"
      In = @( "body" )
      Position = 1
    }
    @{
      Dynamic = "Exclude"
      Name = "excluded_from"
      Required = $true
      Description = "Operations to exclude"
      Type = "array"
      In = @( "body" )
      Enum = @(
        "blocking"
        "extraction"
      )
      Position = 2
    }
    @{
      Dynamic = "GroupIds"
      Name = "groups"
      Required = $true
      Description = "One or more host group identifiers or 'all'"
      Type = "array"
      In = @( "body" )
      Pattern = "(\w{32}|all)"
      Position = 3
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "body" )
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.MlExclusionRespV1"
  }
}