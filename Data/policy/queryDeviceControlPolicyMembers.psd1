@{
  Name = "policy/queryDeviceControlPolicyMembers"
  Path = "/policy/queries/device-control-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "device-control-policies:read"
  Description = "Search for members of a Device Control Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The ID of the Device Control Policy to search for members of"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}