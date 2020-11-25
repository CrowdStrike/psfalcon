@{
  Name = "policy/createSensorUpdatePoliciesV2"
  Path = "/policy/entities/sensor-update/v2"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-update-policies:write"
  Description = "Create Sensor Update Policies"
  Parameters = @(
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The description to use when creating the policy"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "The name to use when creating the policy"
      Position = $null
    }
    @{
      Dynamic = "PlatformName"
      Name = "platform_name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Enum = @(
        "Windows"
        "Mac"
        "Linux"
      )
      Description = "Platform name"
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
    201 = "responses.SensorUpdatePoliciesV2"
    400 = "responses.SensorUpdatePoliciesV2"
    403 = "msa.ErrorsOnly"
    404 = "responses.SensorUpdatePoliciesV2"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV2"
  }
}