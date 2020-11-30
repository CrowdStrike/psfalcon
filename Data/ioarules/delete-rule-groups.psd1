@{
  Name = "ioarules/delete-rule-groups"
  Description = "Delete rule groups by ID."
  Path = "/ioarules/entities/rule-groups/v1"
  Method = "delete"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "ids"
      Required = $true
      Description = "One or more rule group identifiers"
      Type = "array"
      In = @( "query" )
      Position = 1
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Required = $false
      Description = "Comment for tracking purposes"
      Type = "string"
      In = @( "query" )
      Position = 2
    }
  )
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}