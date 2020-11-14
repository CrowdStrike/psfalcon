@{
  Name = "fwmgr/delete-rule-groups"
  Path = "/fwmgr/entities/rule-groups/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Delete Firewall Rule Groups"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more rule group identifiers"
      Position = 1
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Audit log comment for this action"
      Position = 2
    }
  )
  Responses = @{
    200 = "fwmgr.api.QueryResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}