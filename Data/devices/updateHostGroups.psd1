@{
  Name = "devices/updateHostGroups"
  Path = "/devices/entities/host-groups/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "host-group:write"
  Description = "Update Host Groups by specifying the ID of the group and details to update"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Pattern = "\w{32}"
      Description = "The id of the group to update"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new name of the group"
      Position = 2
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new description of the group"
      Position = 3
    }
    @{
      Dynamic = "AssignmentRule"
      Name = "assignment_rule"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "An assignment rule for dynamic groups"
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.HostGroupsV1"
  }
}