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
      Pattern = "\w{32}"
      Required = $true
      Description = "Policy identifier"
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
    200 = "responses.SensorUpdatePoliciesV2"
    400 = "responses.SensorUpdatePoliciesV2"
    403 = "msa.ErrorsOnly"
    404 = "responses.SensorUpdatePoliciesV2"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV2"
  }
}