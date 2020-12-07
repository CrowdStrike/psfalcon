@{
  Name = "policy/createIOAExclusionsV1"
  Method = "post"
  Path = "/policy/entities/ioa-exclusions/v1"
  Description = "Create the IOA exclusions"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "self-service-ioa-exclusions:write"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "groups"
      Type = "array"
      In = @( "body" )
      Pattern = "(\w{32}|all)"
      Required = $true
      Position = 1
      Description = "One or more host group identifiers or 'all'"
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 2
      Description = "Indicator of Attack exclusion name"
    }
    @{
      Dynamic = "PatternId"
      Name = "pattern_id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 3
      Description = "Indicator of Attack pattern identifier"
    }
    @{
      Dynamic = "ImagePath"
      Name = "ifn_regex"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 4
      Description = "Image filename RegEx pattern"
    }
    @{
      Dynamic = "CommandLine"
      Name = "cl_regex"
      Type = "string"
      In = @( "body" )
      Required = $true
      Position = 5
      Description = "Command line RegEx pattern"
    }
    @{
      Dynamic = "PatternName"
      Name = "pattern_name"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 6
      Description = "Indicator of Attack pattern name"
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 7
      Description = "A description of the Indicator of Attack exclusion"
    }
    @{
      Dynamic = "DetectionJson"
      Name = "detection_json"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 8
      Description = $null
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "body" )
      Required = $false
      Position = 9
      Description = "Comment for tracking purposes"
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    default = "responses.IoaExclusionRespV1"
    429 = "msa.ReplyMetaOnly"
    }
}
