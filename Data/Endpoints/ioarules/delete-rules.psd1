@{
  Name = "ioarules/delete-rules"
  Description = "Delete rules from a rule group by ID."
  Path = "/ioarules/entities/rules/v1"
  Method = "delete"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "rule_group_id"
      Required = $true
      Description = "Rule group identifier"
      Type = "string"
      In = @( "query" )
      Pattern = "\w{32}"
      Position = 1
    }
    @{
      Dynamic = "RuleIds"
      Name = "ids"
      Required = $true
      Description = "One or more rule identifiers"
      Type = "array"
      In = @( "query" )
      Position = 2
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "query" )
      Position = 3
    }
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}