@{
  Name = "fwmgr/create-rule-group"
  Path = "/fwmgr/entities/rule-groups/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Create new rule group on a platform for a customer with a name and description and return the ID"
  Parameters = @(
    @{
      Dynamic = "CloneId"
      Name = "clone_id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Copy settings from an existing policy"
      Pattern = "\w{32}"
      Position = $null
    }
    @{
      Dynamic = "Library"
      Name = "library"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "If this flag is set to true then the rules will be cloned from the clone_id from the CrowdStrike Firewall Rule Groups Library."
      Position = $null
    }
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
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Description = "Description of the rule group"
      Required = $false
      Position = $null
    }
    @{
      Dynamic = "Enabled"
      Name = "enabled"
      Type = "bool"
      In = @( "body" )
      Description = "Status of the rule group"
      Required = $true
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Description = "Name of the rule group"
      Required = $true
      Position = $null
    }
    @{
      Dynamic = "Rules"
      Name = "rules"
      Type = "array"
      In = @( "body" )
      Description = "An array of hashtables containing rule properties"
      Required = $false
      Position = $null
    }
  )
  Responses = @{
    201 = "fwmgr.api.QueryResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}