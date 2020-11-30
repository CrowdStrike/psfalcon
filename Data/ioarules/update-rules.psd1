@{
  Name = "ioarules/update-rules"
  Description = "Update rules within a rule group. Return the updated rules."
  Path = "/ioarules/entities/rules/v1"
  Method = "patch"
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
      Description = "Rule group identifier"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Position = 1
    }
    @{
      Dynamic = "GroupVersion"
      Name = "rulegroup_version"
      Required = $true
      Description = "Rule group version"
      Type = "int"
      In = @( "body" )
      Position = 2
    }
    @{
      Dynamic = "RuleUpdates"
      Name = "rule_updates"
      Required = $true
      Description = "An array of hashtables containing rule properties"
      Type = "array"
      In = @( "body" )
      Position = 3
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $true
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "body" )
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.RulesResponse"
  }
}