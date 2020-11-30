@{
  Name = "policy/queryCombinedSensorUpdateBuilds"
  Path = "/policy/combined/sensor-update-builds/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Retrieve available builds for use with Sensor Update Policies"
  Parameters = @(
    @{
      Dynamic = "Platform"
      Name = "platform"
      Type = "string"
      In = @( "query" )
      Required = $false
      Enum = @(
        "linux"
        "mac"
        "windows"
      )
      Description = "The platform to return builds for"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.SensorUpdateBuildsV1"
  }
}