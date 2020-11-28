@{
  Name = "devices/QueryHiddenDevices"
  Path = "/devices/queries/devices-hidden/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "devices:read"
  Description = "Retrieve hidden hosts that match the provided filter criteria."
  Parameters = @(
    @{
      Dynamic = "Hidden"
      Type = "switch"
      Required = $true
      Description = "Search for hidden hosts"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}