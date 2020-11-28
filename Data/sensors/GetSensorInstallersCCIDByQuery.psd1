@{
  Name = "sensors/GetSensorInstallersCCIDByQuery"
  Path = "/sensors/queries/installers/ccid/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-installers:read"
  Description = "Get CCID to use with sensor installers"
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}