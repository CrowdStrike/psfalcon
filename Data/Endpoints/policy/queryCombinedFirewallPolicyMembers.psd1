@{
  Name = "policy/queryCombinedFirewallPolicyMembers"
  Path = "/policy/combined/firewall-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The ID of the Firewall Policy to search for members of"
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