@{
  Name = "sensors/GetSensorInstallersEntities"
  Path = "/sensors/entities/installers/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-installers:read"
  Description = "Get sensor installer details by provided SHA256 IDs"
  Parameters = @(
    @{
      Dynamic = "FileIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the installers"
      Position = 1
    }
  )
  Responses = @{
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    default = "domain.SensorInstallersV1"
  }
}