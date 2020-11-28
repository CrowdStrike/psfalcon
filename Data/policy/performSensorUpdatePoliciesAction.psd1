@{
  Name = "policy/performSensorUpdatePoliciesAction"
  Path = "/policy/entities/sensor-update-actions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-update-policies:write"
  Description = "Perform actions on Sensor Update Policies"
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
      Position = $null
    }
    @{
      Dynamic = "PolicyId"
      Name = "ids"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Required = $true
      Description = "Policy identifier"
      Position = $null
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
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.SensorUpdatePoliciesV1"
    400 = "responses.SensorUpdatePoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.SensorUpdatePoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV1"
  }
}