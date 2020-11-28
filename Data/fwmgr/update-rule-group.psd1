@{
  Name = "fwmgr/update-rule-group"
  Path = "/fwmgr/entities/rule-groups/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Update name description or enabled status of a rule group or create edit delete or reorder rules"
  Parameters = @(
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Audit log comment for this action"
      Position = $null
    }
    @{
      Dynamic = "DiffOperations"
      Name = "diff_operations"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "An array of hashtables containing rule or rule group changes"
      Position = $null
    }
    @{
      Dynamic = "GroupId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "A firewall rule group identifier"
      Position = $null
    }
    @{
      Dynamic = "RuleIds"
      Name = "rule_ids"
      Type = "array"
      In = @( "body" )
      Required = $false
      Description = "One or more firewall rule identifiers"
      Position = $null
    }
    @{
      Dynamic = "RuleVersions"
      Name = "rule_versions"
      Type = "array"
      In = @( "body" )
      Required = $false
      Description = "Rule version value"
      Position = $null
    }
    @{
      Dynamic = "Tracking"
      Name = "tracking"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Tracking value"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.QueryResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}