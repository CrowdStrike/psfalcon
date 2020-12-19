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
      Description = "The ID of the Sensor Update Policy to search for members of"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.PolicyMembersRespV1"
  }
}