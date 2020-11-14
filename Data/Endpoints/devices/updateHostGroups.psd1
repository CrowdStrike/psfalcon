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
      Dynamic = "AssignmentRule"
      Name = "assignment_rule"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new assignment rule of the group. Note: If the group type is static this field cannot be updated manually"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new description of the group"
      Position = $null
    }
    @{
      Dynamic = "GroupId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Pattern = "\w{32}"
      Description = "The id of the group to update"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new name of the group"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.HostGroupsV1"
    400 = "responses.HostGroupsV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.HostGroupsV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupsV1"
  }
}