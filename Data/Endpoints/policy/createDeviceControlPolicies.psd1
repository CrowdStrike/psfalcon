@{
  Name = "policy/createDeviceControlPolicies"
  Path = "/policy/entities/device-control/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "device-control-policies:write"
  Description = "Create Device Control Policies"
  Parameters = @(
    @{
      Dynamic = "CloneId"
      Name = "clone_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Copy settings from an existing policy"
      Pattern = "\w{32}"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Policy description"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "Policy name"
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
    201 = "responses.DeviceControlPoliciesV1"
    400 = "responses.DeviceControlPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.DeviceControlPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.DeviceControlPoliciesV1"
  }
}