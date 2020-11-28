@{
  Name = "policy/queryCombinedDeviceControlPolicyMembers"
  Path = "/policy/combined/device-control-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "device-control-policies:read"
  Description = "Search for members of a Device Control Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria"
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
    200 = "responses.PolicyMembersRespV1"
    400 = "responses.PolicyMembersRespV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.PolicyMembersRespV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.PolicyMembersRespV1"
  }
}