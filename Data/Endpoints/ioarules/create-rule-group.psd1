@{
  Name = "ioarules/create-rule-group"
  Description = "Create a rule group for a platform with a name and an optional description. Returns the rule group."
  Path = "/ioarules/entities/rule-groups/v1"
  Method = "post"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "Platform"
      Name = "platform"
      Required = $true
      Type = "string"
      In = @( "body" )
      Enum = @(
        "linux"
        "mac"
        "windows"
      )
      Description = "Operating system platform"
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
      Required = $false
      Type = "string"
      In = @( "body" )
      Description = "Rule group description"
      Position = 3
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Type = "string"
      In = @( "body" )
      Description = "Rule group comment"
      Position = 4
    }
  )
  Responses = @{
    201 = "api.RuleGroupsResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}