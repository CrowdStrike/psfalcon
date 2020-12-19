@{
  Name = "policy/updateSensorUpdatePoliciesV2"
  Path = "/policy/entities/sensor-update/v2"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-update-policies:write"
  Description = "Update Sensor Update Policies by specifying the ID of the policy and details to update"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Pattern = "\w{32}"
      Description = "Policy identifier"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The new name to assign to the policy"
      Position = 2
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The new description to assign to the policy"
      Position = 3
    }
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "hashtable"
      In = @( "body" )
      Parent = "resources"
      Description = "A hashtable defining policy settings"
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.SensorUpdatePoliciesV2"
  }
}