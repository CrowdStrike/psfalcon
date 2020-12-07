@{
  Name = "policy/createSVExclusionsV1"
  Method = "post"
  Path = "/policy/entities/sv-exclusions/v1"
  Description = "Create the sensor visibility exclusions"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-visibility-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "groups"
      Type = "array"
      In = @( "body" )
      Required = $true
      Pattern = "(\w{32}|all)"
      Position = 1
      Description = "One or more host group identifiers or 'all'"
    }
    @{
      Dynamic = "Pattern"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 2
      Description = "The file or folder path to exclude"
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 3
      Description = "Comment for tracking purposes"
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    default = "responses.MlExclusionRespV1"
    429 = "msa.ReplyMetaOnly"
    }
}
