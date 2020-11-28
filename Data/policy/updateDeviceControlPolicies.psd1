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
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new description to assign to the policy"
      Position = $null
    }
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "The id of the policy to update"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new name to assign to the policy"
      Position = $null
    }
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "hashtable"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "A hashtable defining policy settings"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.DeviceControlPoliciesV1"
    400 = "responses.DeviceControlPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.DeviceControlPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.DeviceControlPoliciesV1"
  }
}