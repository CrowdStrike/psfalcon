@{
  Name = "policy/updateSensorVisibilityExclusionsV1"
  Method = "patch"
  Path = "/policy/entities/sv-exclusions/v1"
  Description = "Update the sensor visibility exclusions"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-visibility-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "ExclusionId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 1
      Description = "Exclusion identifier"
    }
    @{
      Dynamic = "Value"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 2
      Description = "The file or folder path to exclude"
    }
    @{
      Dynamic = "GroupIds"
      Name = "groups"
      Type = "array"
      In = @( "body" )
      Required = $false
      Pattern = "(\w{32}|all)"
      Position = 3
      Description = "One or more host group identifiers or 'all'"
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 4
      Description = "Comment for tracking purposes"
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    default = "responses.SvExclusionRespV1"
    429 = "msa.ReplyMetaOnly"
    }
}
