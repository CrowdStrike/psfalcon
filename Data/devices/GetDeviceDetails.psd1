@{
  Name = "devices/GetDeviceDetails"
  Path = "/devices/entities/devices/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "devices:read"
  Description = "List detailed Host information"
  Parameters = @(
    @{
      Dynamic = "HostIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Max = 1000
      Required = $true
      Pattern = "\w{32}"
      Description = "The host agentIDs used to get details on"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.DeviceDetailsResponseSwagger"
  }
}