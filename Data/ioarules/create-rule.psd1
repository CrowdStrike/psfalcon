@{
  Name = "ioarules/create-rule"
  Description = "Create a rule within a rule group. Returns the rule."
  Path = "/ioarules/entities/rules/v1"
  Method = "post"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "rulegroup_id"
      Required = $true
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Description = "Rule group identifier"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Required = $true
      Type = "string"
      In = @( "body" )
      Description = "Rule name"
      Position = 2
    }
    @{
      Dynamic = "Severity"
      Name = "pattern_severity"
      Required = $true
      Type = "string"
      In = @( "body" )
      Enum = @(
        "critical"
        "high"
        "medium"
        "low"
        "informational"
      )
      Description = "Rule severity"
      Position = 3
    }
    @{
      Dynamic = "TypeId"
      Name = "ruletype_id"
      Required = $true
      Type = "string"
      In = @( "body" )
      Description = "Rule type identifier"
      Position = 4
    }
    @{
      Dynamic = "DispositionId"
      Name = "disposition_id"
      Required = $true
      Type = "int"
      In = @( "body" )
      Description = "Rule disposition identifier"
      Position = 5
    }
    @{
      Dynamic = "FieldValues"
      Name = "field_values"
      Required = $true
      Type = "array"
      In = @( "body" )
      Description = "An array of hashtables containing rule properties"
      Position = 6
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Required = $false
      Type = "string"
      In = @( "body" )
      Description = "Rule description"
      Position = 7
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Type = "string"
      In = @( "body" )
      Description = "Comment for tracking purposes"
      Position = 8
    }
  )
  Responses = @{
    201 = "api.RulesResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}