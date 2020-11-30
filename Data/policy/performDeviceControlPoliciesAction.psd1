@{
  Name = "policy/performDeviceControlPoliciesAction"
  Path = "/policy/entities/device-control-actions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "device-control-policies:write"
  Description = "Perform actions on Device Control Policies"
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "action_name"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "add-host-group"
        "disable"
        "enable"
        "remove-host-group"
      )
      Description = "Action to perform"
      Position = 1
    }
    @{
      Dynamic = "PolicyId"
      Name = "ids"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Required = $true
      Description = "Policy identifier"
      Position = 2
    }
    @{
      Dynamic = "GroupId"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Parent = "action_parameters"
      Pattern = "\w{32}"
      Required = $false
      Description = "Host Group identifier used when adding or removing host groups"
      Position = 3
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.DeviceControlPoliciesV1"
  }
}