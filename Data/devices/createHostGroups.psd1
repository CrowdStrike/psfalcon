@{
  Name = "devices/createHostGroups"
  Path = "/devices/entities/host-groups/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "host-group:write"
  Description = "Create Host Groups"
  Parameters = @(
    @{
      Dynamic = "AssignmentRule"
      Name = "assignment_rule"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "An FQL filter expression to dynamically assign hosts"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Group description"
      Position = $null
    }
    @{
      Dynamic = "GroupType"
      Name = "group_type"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Enum = @(
        "static"
        "dynamic"
      )
      Description = "Group type"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "Group name"
      Position = $null
    }
  )
  Responses = @{
    201 = "responses.HostGroupsV1"
    400 = "responses.HostGroupsV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupsV1"
  }
}