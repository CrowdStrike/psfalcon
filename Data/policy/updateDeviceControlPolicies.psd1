@{
  Name = "policy/updateDeviceControlPolicies"
  Path = "/policy/entities/device-control/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "device-control-policies:write"
  Description = "Update Device Control Policies by specifying the ID of the policy and details to update"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Pattern = "\w{32}"
      Description = "The id of the policy to update"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new name to assign to the policy"
      Position = 2
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new description to assign to the policy"
      Position = 3
    }
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "hashtable"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "A hashtable defining policy settings"
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.DeviceControlPoliciesV1"
  }
}