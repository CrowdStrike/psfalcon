@{
  Name = "policy/queryCombinedSensorUpdatePolicyMembers"
  Path = "/policy/combined/sensor-update-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Search for members of a Sensor Update Policy"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Pattern = "\w{32}"
      Required = $false
      Description = "The ID of the Sensor Update Policy to search for members of"
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