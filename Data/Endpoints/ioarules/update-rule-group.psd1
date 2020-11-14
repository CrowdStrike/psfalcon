@{
  Name = "ioarules/update-rule-group"
  Description = "Update a rule group."
  Path = "/ioarules/entities/rule-groups/v1"
  Method = "patch"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "id"
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
      Description = "Rule group name"
      Position = 2
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Required = $true
      Type = "string"
      In = @( "body" )
      Description = "Rule group description"
      Position = 3
    }
    @{
      Dynamic = "Enabled"
      Name = "enabled"
      Required = $true
      Type = "bool"
      In = @( "body" )
      Description = "Rule group status"
      Position = 4
    }
    @{
      Dynamic = "Version"
      Name = "rulegroup_version"
      Required = $true
      Type = "int"
      In = @( "body" )
      Description = "Rule group version"
      Position = 5
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $true
      Type = "string"
      In = @( "body" )
      Description = "Comment for tracking purposes"
      Position = 6
    }
  )
  Responses = @{
    200 = "api.RuleGroupsResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}